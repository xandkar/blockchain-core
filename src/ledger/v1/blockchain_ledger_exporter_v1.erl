%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Ledger Exporter ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_ledger_exporter_v1).

-export([
    export/1,
    export_accounts_csv/2
]).

-spec export(blockchain_ledger_v1:ledger()) -> any().
export(Ledger) ->
    [
        {securities, export_securities(Ledger)},
        {accounts, export_accounts(Ledger)},
        {gateways, export_gateways(Ledger)},
        {chain_vars, export_chain_vars(Ledger)},
        {dcs, export_dcs(Ledger)}
    ].

-spec export_accounts(blockchain_ledger_v1:ledger()) -> list().
export_accounts(Ledger) ->
    lists:foldl(
        fun({Address, Entry}, Acc) ->
            [[{address, libp2p_crypto:bin_to_b58(Address)},
              {balance, blockchain_ledger_entry_v1:balance(Entry)}] | Acc]
        end,
        [],
        maps:to_list(blockchain_ledger_v1:entries(Ledger))
    ).

-spec export_accounts_csv(
    blockchain_ledger_v1:ledger(),
    file:name_all()
) -> ok.
export_accounts_csv(Ledger, OutFilePatch) ->
    {ok, File} = file:open(OutFilePatch, [write]),
    HeadRow =
        [
            "status",
            "net-type",
            "key-type",
            "key-size",
            "pubkey-helium-b58",
            "pubkey-solana-b58",
            "bones",
            "hnt"
        ],
    ok = file:write(File, [lists:join(",", HeadRow), "\n"]),
    lists:foldl(
        fun({<<PubKeyHelium/binary>>, Entry}, ok) ->
            <<NetTypeInt:4, KeyTypeInt:4, PubKey/binary>> = PubKeyHelium,
            Net =
                case NetTypeInt of
                    0 -> mainnet;
                    1 -> testnet;
                    _ -> invalid
                end,
            PubKeyHeliumB58 = libp2p_crypto:bin_to_b58(PubKeyHelium),
            PubKeySolanaB58 = bs58(PubKey),
            BalanceBones = blockchain_ledger_entry_v1:balance(Entry),
            BalanceHNT = BalanceBones / 100_000_000,
            KeySize = integer_to_list(byte_size(PubKey)),
            NetTypeIntStr = integer_to_list(NetTypeInt),
            KeyTypeIntStr = integer_to_list(KeyTypeInt),
            MakeRow =
                fun (Status, KeyTypeStr) ->
                        [
                            Status,
                            NetTypeIntStr,
                            KeyTypeStr,
                            KeySize,
                            PubKeyHeliumB58,
                            PubKeySolanaB58,
                            integer_to_list(BalanceBones),
                            io_lib:format("~.10f", [BalanceHNT])
                        ]
                end,
            Row =
                case lists:member(Net, [mainnet, testnet]) of
                    false ->
                        MakeRow("err-net", KeyTypeIntStr);
                    true ->
                        case libp2p_crypto:bin_to_pubkey_2(Net, PubKeyHelium) of
                            {ok, {KeyTypeAtom, _}} ->
                                MakeRow("ok", atom_to_list(KeyTypeAtom));
                            {error, {bad_key, _}} ->
                                MakeRow("err-key", KeyTypeIntStr)
                        end
                end,
            ok = file:write(File, [lists:join(",", Row), "\n"])
        end,
        ok,
        maps:to_list(blockchain_ledger_v1:entries(Ledger))
    ),
    ok = file:close(File).

bs58(Data0) ->
    ScratchFilePath = scratch_file_path(),
    ok = file:write_file(ScratchFilePath, Data0),
    ExePath = "/home/xand/.cargo/bin/bs58",
    % XXX bs58 only accepts stdin, but sending it via port didn't work.
    {0, Data1} = os_cmd(ExePath ++ " < " ++ ScratchFilePath),
    Data1.

scratch_file_path() ->
    Key = {?MODULE, scratch_file_path},
    case get(Key) of
        undefined ->
            {0, Path0} = os_cmd("mktemp"),
            Path = Path0 -- "\n",
            put(Key, Path),
            Path;
        Path ->
            Path
    end.

os_cmd(Cmd) ->
    PortId = open_port({spawn, Cmd}, [stream, exit_status, use_stdio, in, eof]),
    os_cmd_collect(PortId, []).

os_cmd_collect(PortId, Data) ->
    receive
        {PortId, {data, Datum}} ->
            os_cmd_collect(PortId, [Datum | Data]);
        {PortId, eof} ->
            port_close(PortId),
            receive
                {PortId, {exit_status, ExitStatusCode}} ->
                    {ExitStatusCode, lists:flatten(lists:reverse(Data))}
            end
    end.

-spec export_gateways(blockchain_ledger_v1:ledger()) -> list().
export_gateways(Ledger) ->
    lists:foldl(
        fun({GatewayAddress, Gateway}, Acc) ->
            [[{gateway_address, libp2p_crypto:bin_to_b58(GatewayAddress)},
              {owner_address, libp2p_crypto:bin_to_b58(blockchain_ledger_gateway_v2:owner_address(Gateway))},
              {location, blockchain_ledger_gateway_v2:location(Gateway)},
              {nonce, blockchain_ledger_gateway_v2:nonce(Gateway)}] | Acc]
        end,
        [],
        maps:to_list(blockchain_ledger_v1:active_gateways(Ledger))
    ).

-spec export_securities(blockchain_ledger_v1:ledger()) -> list().
export_securities(Ledger) ->
    lists:foldl(
        fun({Address, SecurityEntry}, Acc) ->
            [[{address, libp2p_crypto:bin_to_b58(Address)},
              {token, blockchain_ledger_security_entry_v1:balance(SecurityEntry)}] | Acc]
        end,
        [],
        maps:to_list(blockchain_ledger_v1:securities(Ledger))
    ).

-spec export_dcs(blockchain_ledger_v1:ledger()) -> list().
export_dcs(Ledger) ->
    lists:foldl(
        fun({Address, DCEntry}, Acc) ->
            [[{address, libp2p_crypto:bin_to_b58(Address)},
              {dc_balance, blockchain_ledger_data_credits_entry_v1:balance(DCEntry)}] | Acc]
        end,
        [],
        maps:to_list(blockchain_ledger_v1:dc_entries(Ledger))
    ).

export_chain_vars(Ledger) ->
    lists:sort(blockchain_ledger_v1:snapshot_vars(Ledger)).
