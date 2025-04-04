%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Transaction Bundle ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_txn_bundle_v1).

-behavior(blockchain_txn).
-behavior(blockchain_json).

-include("blockchain_json.hrl").
-include("blockchain_records_meta.hrl").
-include("blockchain_vars.hrl").
-include_lib("helium_proto/include/blockchain_txn_pb.hrl").

-define(MAX_BUNDLE_SIZE, 5).

-export([
    new/1,
    hash/1,
    absorb/2,
    sign/2,
    fee/1,
    fee_payer/2,
    txns/1,
    is_valid/2,
    is_well_formed/1,
    is_prompt/2,
    print/1,
    json_type/0,
    to_json/2
]).

-define(T, blockchain_txn_bundle_v1_pb).

-type t() :: txn_bundle().
-type txn_bundle() :: #?T{}.

-export_type([t/0, txn_bundle/0]).

-spec new(Txns :: blockchain_txn:txns()) -> txn_bundle().
new(Txns) ->
    #blockchain_txn_bundle_v1_pb{transactions=Txns}.

-spec hash(txn_bundle()) -> blockchain_txn:hash().
hash(#blockchain_txn_bundle_v1_pb{transactions=Txns}) ->
    TxnHashes = [blockchain_txn:hash(T) || T <- Txns],
    crypto:hash(sha256, TxnHashes).

-spec absorb(txn_bundle(), blockchain:blockchain()) -> ok | {error, atom()} | {error, {atom(), any()}}.
absorb(#blockchain_txn_bundle_v1_pb{transactions=Txns}=_Txn, Chain) ->
    lists:foreach(fun(T) -> blockchain_txn:absorb(T, Chain) end, Txns).

-spec sign(txn_bundle(), libp2p_crypto:sig_fun()) -> txn_bundle().
sign(TxnBundle, _SigFun) ->
    %% bundles are not signed
    TxnBundle.

-spec fee(txn_bundle()) -> 0.
fee(_TxnBundle) ->
    0.

-spec fee_payer(txn_bundle(), blockchain_ledger_v1:ledger()) -> libp2p_crypto:pubkey_bin() | undefined.
fee_payer(_TxnBundle, _Ledger) ->
    undefined.

-spec txns(txn_bundle()) -> blockchain_txn:txns().
txns(#blockchain_txn_bundle_v1_pb{transactions=Txns}) ->
    Txns.

-spec is_valid(txn_bundle(), blockchain:blockchain()) -> ok | {error, atom()} | {error, {atom(), any()}}.
is_valid(#blockchain_txn_bundle_v1_pb{transactions=Txns}=Txn, Chain) ->
    TxnBundleSize = length(Txns),
    MaxBundleSize = max_bundle_size(Chain),

    %% check that the bundle contains minimum two transactions
    case TxnBundleSize < 2 of
        true ->
            {error, {invalid_min_bundle_size, Txn}};
        false ->
            %% check that the bundle size doesn't exceed allowed max_bundle_size var
            case TxnBundleSize > MaxBundleSize of
                true ->
                    {error, {bundle_size_exceeded, {TxnBundleSize, MaxBundleSize}}};
                false ->
                    %% check that there are no bundles in the bundle txn
                    case lists:any(fun(T) ->
                                           blockchain_txn:type(T) == blockchain_txn_bundle_v1
                                   end,
                                   Txns) of
                        true ->
                            {error, {invalid_bundleception, Txn}};
                        false ->
                            %% speculative check whether the bundle is valid
                            case speculative_absorb(Txn, Chain) of
                                [] ->
                                    ok;
                                List ->
                                    {error, {invalid_bundled_txns, List}}
                            end
                    end
            end
    end.

-spec is_well_formed(t()) -> ok | {error, {contract_breach, any()}}.
is_well_formed(#?T{}=T) ->
    %% Min size is static, so we can check it here without any other info, but
    %% max size check has to be deferred for later, since we first need to
    %% lookup the current max in a chain var, for which we need the chain param.
    data_contract:check(
        ?RECORD_TO_KVL(?T, T),
        {kvl, [{transactions, {list, {min, 2}, blockchain_txn_contract:txn()}}]}
    ).

-spec is_prompt(t(), blockchain_ledger_v1:ledger()) ->
    {ok, blockchain_txn:is_prompt()} | {error, any()}.
is_prompt(#?T{transactions=[_, _]=Txs}, Ledger) ->
    %% TODO Maybe something more sophisticated than this brutal all-or-nothing?
    lists:foldl(
        fun (_, {error, _}=Err) ->
                Err;
            (_, {ok, no}=No) ->
                No;
            (_, {ok, {not_yet, _}}) ->
                {ok, no};
            (Tx, {ok, yes}) ->
                TxType = blockchain_txn:type(Tx),
                TxType:is_prompt(Tx, Ledger)
        end,
        {ok, yes},
        Txs
    ).

-spec print(txn_bundle()) -> iodata().
print(#blockchain_txn_bundle_v1_pb{transactions=Txns}) ->
    io_lib:format("type=bundle, txns=~p", [
                                           [blockchain_txn:print(T) || T <- Txns]
                                          ]).

json_type() ->
    <<"bundle_v1">>.

-spec to_json(txn_bundle(), blockchain_json:opts()) -> blockchain_json:json_object().
to_json(Txn, Opts) ->
    #{
      type => ?MODULE:json_type(),
      hash => ?BIN_TO_B64(hash(Txn)),
      fee => fee(Txn),
      txns => [blockchain_txn:to_json(T, Opts) || T <- txns(Txn)]
     }.

-spec max_bundle_size(blockchain:blockchain()) -> pos_integer().
max_bundle_size(Chain) ->
    Ledger = blockchain:ledger(Chain),
    case blockchain:config(?max_bundle_size, Ledger) of
        {error, _} ->
            %% If max bundle size is not set, default to 5
            ?MAX_BUNDLE_SIZE;
        {ok, Size} ->
            Size
    end.

-spec speculative_absorb(txn_bundle(), blockchain:blockchain()) -> [blockchain_txn:txns()].
speculative_absorb(#blockchain_txn_bundle_v1_pb{transactions=Txns}, Chain0) ->
    InitLedger = blockchain:ledger(Chain0),
    %% Check that the bundled transactions can be absorbed in order in this ledger context
    LedgerContext = blockchain_ledger_v1:new_context(InitLedger),
    Chain = blockchain:ledger(LedgerContext, Chain0),
    InvalidTxns = lists:foldl(fun(Txn, Acc) ->
                                      case blockchain_txn:is_valid(Txn, Chain) of
                                          {error, _} ->
                                              [Txn | Acc];
                                          ok ->
                                              case blockchain_txn:absorb(Txn, Chain) of
                                                  {error, _} ->
                                                      [Txn | Acc];
                                                  ok ->
                                                      Acc
                                              end
                                      end
                              end,
                              [],
                              Txns),
    blockchain_ledger_v1:delete_context(LedgerContext),
    InvalidTxns.

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").
-include_lib("helium_proto/include/blockchain_txn_assert_location_v1_pb.hrl").

is_well_formed_test_() ->
    Tx = blockchain_txn_assert_location_v1:gen_new_valid(),
    [
        ?_assertEqual(
            {error, {contract_breach, {invalid_kvl_pairs, [{transactions, {not_a_list, undefined}}]}}},
            is_well_formed(#?T{transactions=undefined})
        ),
        ?_assertEqual(
            {error, {contract_breach, {invalid_kvl_pairs, [{transactions, {list_wrong_size, 0, {min, 2}}}]}}},
            is_well_formed(#?T{transactions=[]})
        ),
        ?_assertEqual(
            {error, {contract_breach, {invalid_kvl_pairs, [{transactions, {list_wrong_size, 1, {min, 2}}}]}}},
            is_well_formed(#?T{transactions=[Tx]})
        ),
        ?_assertEqual(
            ok,
            is_well_formed(#?T{
                transactions = [Tx, Tx]
            })
        ),
        ?_assertEqual(
            {error, {contract_breach, {invalid_kvl_pairs, [{transactions, {list_contains_invalid_elements, [{txn_invalid_or_wrong_type, trust_me_im_a_txn}]}}]}}},
            is_well_formed(#?T{transactions = [Tx, Tx, trust_me_im_a_txn]})
        ),
        ?_assertMatch(
            {error, {contract_breach, {invalid_kvl_pairs, [{transactions, {list_contains_invalid_elements, [
                {txn_invalid_or_wrong_type, #blockchain_txn_assert_location_v1_pb{}}
            ]}}]}}},
            is_well_formed(#?T{transactions = [
                Tx,
                Tx#blockchain_txn_assert_location_v1_pb{gateway = undefined}
            ]})
        )
    ].

-endif.
