pub const std_os_options: std.Options.OperatingSystem = horizon.default_std_os_options;
pub const panic = horizon.debug.simple_errdisp_panic;
pub const zitrus_options: zitrus.Options = .{
    .stack_size = switch (@import("builtin").mode) {
        else => 16 * 1024, // We'll stack overflow otherwise
        .ReleaseSafe, .ReleaseSmall, .ReleaseFast => null, // Use the kernel-provided stack (4096 bytes in this case)
    },
};

const State = horizon.module.State(
    &.{},
    &.{"ps:ps"},
    &.{.handled},
    &.{20},
);

pub fn main() void {
    const srv = assertResult(ServiceManager.openWithResult());
    defer srv.close();

    const tls = horizon.tls.get();
    const ipc = &tls.ipc;

    assertResult(srv.sendWithResult(.RegisterClient, .{}, .{}));

    var state: State = .empty;
    state.initServices(srv);
    defer state.deinitServices(srv);

    const ps9: Ps9 = assertResult(Ps9.openWithResult(srv));
    defer ps9.close();

    const fs: FsUser = assertResult(FsUser.openWithResult(srv, .user));
    defer fs.close();

    // Here it uses `InitializeWithSdkVersion` but we're not using any :p
    assertResult(fs.sendWithResult(.Initialize, .{}, .{}));

    const mcu: McuPls = assertResult(McuPls.openWithResult(srv));
    defer mcu.close();

    var ctx: Ps.rsa.Context = undefined;
    var stop = false;
    loop: while (true) {
        if (state.last_reply_to.session == Session.Server.none) {
            if (stop and state.remotes == 0) break :loop;

            ipc.packed_command.header = .none;
        }

        ipc.static.buffers[0] = .init(Ps.rsa.Context, (&ctx)[0..1], 0);
        switch (state.next(srv)) {
            .notification => |id| switch (id) {
                .must_terminate => stop = true,
                else => {},
            },
            .unhandled_session_accepted => unreachable, // All our sessions are handled
            .handled_session_accepted, .handled_session_closed => {},
            .handled_session_request => |port| switch (port) {
                .@"ps:ps" => if (ipc.readRequestId(Ps.command.Id)) |id| switch (id) {
                    .rsa_sign_sha256 => if (ipc.readRequest(Ps.command.RsaSignSha256)) |req|
                        ipc.writeResponse(Ps.command.RsaSignSha256, blk: {
                            const sign_res = ps9.sendWithResult(.RsaSignSha256, .init(req.sha256, req.signature.slice, &ctx), .{});
                            break :blk .of(sign_res.code, req.signature);
                        }),
                    .rsa_verify_sha256 => if (ipc.readRequest(Ps.command.RsaVerifySha256)) |req|
                        ipc.writeResponse(Ps.command.RsaVerifySha256, blk: {
                            const verify_res = ps9.sendWithResult(.RsaVerifySha256, .init(req.sha256, req.signature.slice, &ctx), .{});
                            break :blk .of(verify_res.code, req.signature);
                        }),
                    .aes_crypt => if (ipc.readRequest(Ps.command.AesCrypt)) |req|
                        ipc.writeResponse(Ps.command.AesCrypt, blk: {
                            const size = switch (req.algorithm) {
                                .encrypt_ccm, .decrypt_ccm => break :blk .of(.ps_invalid_selection, .init(@splat(0), req.input.slice, req.output.slice)),
                                .encrypt_cbc, .decrypt_cbc => @min(req.output.slice.len, req.input.slice.len) & ~@as(u32, 0xF),
                                else => @min(req.output.slice.len, req.input.slice.len),
                            };

                            const op_res = ps9.sendWithResult(
                                .AesCrypt, 
                                .init(req.iv_ctr, req.algorithm, req.key, req.input.slice[0..size], req.output.slice[0..size]),
                                .{},
                            );

                            break :blk .of(op_res.code, .init(op_res.value.feedback_iv_ctr, req.input.slice, req.output.slice));
                        }),
                    .aes_ccm_crypt => if (ipc.readRequest(Ps.command.AesCcmCrypt)) |req|
                        ipc.writeResponse(Ps.command.AesCcmCrypt, blk: {
                            const input_size, const output_size = switch (req.algorithm) {
                                .encrypt_ccm => .{req.cbc_mac_data_size + req.data_size, req.data_size + req.mac_size},
                                .decrypt_ccm => .{req.cbc_mac_data_size + req.data_size + req.mac_size, req.data_size},
                                else => break :blk .of(.ps_invalid_selection, .init(req.input.slice, req.output.slice)),
                            };

                            const isAligned = std.mem.isAligned;
                            if (!isAligned(req.cbc_mac_data_size, 16) or !isAligned(req.mac_size, 2) or req.mac_size > 16) break :blk .of(
                                .ps_invalid_size,
                                .init(req.input.slice, req.output.slice),
                            );

                            // Not in the original binary but... we can always be safer
                            if (input_size > req.input.slice.len or output_size > req.output.slice.len) break :blk .of(.ps_invalid_size, .init(req.input.slice, req.output.slice));

                            const op_res = ps9.sendWithResult(
                                .AesCcmCrypt, 
                                .init(req.cbc_mac_data_size, req.data_size, req.mac_size, req.nonce, req.algorithm, req.key, req.input.slice[0..input_size], req.output.slice[0..output_size]),
                                .{},
                            );

                            break :blk .of(op_res.code, .init(req.input.slice, req.output.slice));
                        }),
                    .get_game_card_uid => if (ipc.readRequest(Ps.command.GetGameCardUid)) |req|
                        ipc.writeResponse(
                            Ps.command.GetGameCardUid,
                            getGameCardProperty(Ps9.command.GetGameCardUid.Response, .GetGameCardUid, fs, ps9, @enumFromInt(@intFromEnum(req.pid)))
                        ),
                    .get_game_card_maker_encrypted_uid => if (ipc.readRequest(Ps.command.GetGameCardMakerEncryptedUid)) |req|
                        ipc.writeResponse(
                            Ps.command.GetGameCardMakerEncryptedUid,
                            getGameCardProperty(Ps9.command.GetGameCardMakerEncryptedUid.Response, .GetGameCardMakerEncryptedUid, fs, ps9, @enumFromInt(@intFromEnum(req.pid)))
                        ),
                    .is_game_card_autostarted => if (ipc.readRequest(Ps.command.IsGameCardAutostarted)) |req|
                        ipc.writeResponse(
                            Ps.command.IsGameCardAutostarted,
                            getGameCardProperty(Ps9.command.IsGameCardAutostarted.Response, .IsGameCardAutostarted, fs, ps9, @enumFromInt(@intFromEnum(req.pid)))
                        ),
                    .get_game_card_maker => if (ipc.readRequest(Ps.command.GetGameCardMaker)) |req|
                        ipc.writeResponse(
                            Ps.command.GetGameCardMaker,
                            getGameCardProperty(Ps9.command.GetGameCardMaker.Response, .GetGameCardMaker, fs, ps9, @enumFromInt(@intFromEnum(req.pid)))
                        ),
                    .get_local_friend_code_seed => if (ipc.readRequest(Ps.command.GetLocalFriendCodeSeed)) |_|
                        ipc.writeResponse(Ps.command.GetLocalFriendCodeSeed, .of(.success, assertResult(ps9.sendWithResult(.GetLocalFriendCodeSeed, {}, .{})))),
                    .get_device_id => if (ipc.readRequest(Ps.command.GetDeviceId)) |_|
                        ipc.writeResponse(Ps.command.GetDeviceId, .of(.success, assertResult(ps9.sendWithResult(.GetDeviceId, {}, .{})))),
                    .seed_random => if (ipc.readRequest(Ps.command.SeedRandom)) |_|
                        ipc.writeResponse(Ps.command.SeedRandom, .of(.success, seedRandom(ps9, mcu))),
                    .next_random_bytes => if (ipc.readRequest(Ps.command.NextRandomBytes)) |req|
                        ipc.writeResponse(Ps.command.NextRandomBytes, .of(.success, blk: {
                            seedRandom(ps9, mcu); 
                            _ = assertResult(ps9.sendWithResult(.NextRandomBytes, .init(req.output.slice), .{}));
                            break :blk req.output;
                        })),
                    .set_aes_key,
                    .amiibo_generate_hmac,
                    .amiibo_generate_key_data,
                    .amiibo_crypt,
                    .amiibo_crypt_dev,
                    => {
                        // NOTE: Amiibo commands *are* implemented in ps but they will fail eventually; 
                        // set_aes_key doesn't even passthrough the parameters.
                        ipc.packed_command.header = .invalid;
                        ipc.packed_command.parameters[0] = @bitCast(Code.os_not_implemented);
                    },
                },
            },
        }
    }
}

fn getGameCardProperty(comptime Response: type, comptime cmd: @EnumLiteral(), fs: FsUser, ps9: Ps9, pid: horizon.Process.Id) horizon.Result(Response) {
    return switch (fs.sendWithResult(.GetProgramLaunchInfo, pid, .{}).cases()) {
        .success => |r| .of(.success, switch (r.value.media_type) {
            .nand, .sd => std.mem.zeroes(Response),
            .game_card => assertResult(ps9.sendWithResult(cmd, {}, .{})),
        }),
        .failure => .of(.ps_not_found, undefined),
    };
}

fn seedRandom(ps9: Ps9, mcu: McuPls) void {
    var buffer: [20]u8 = undefined;
    buffer[0..8].* = @bitCast(horizon.getSystemTick());
    buffer[8..15].* = @bitCast(assertResult(mcu.sendWithResult(.GetRealtime, {}, .{})));
    buffer[15..17].* = @bitCast(assertResult(mcu.sendWithResult(.GetTickCounter, {}, .{})));
    // The original binary does not write to buffer[17..] (?)
    // using stack as entropy?
    _ = assertResult(ps9.sendWithResult(.SeedRandom, .init(&buffer), .{}));
}

const assertResult = ErrorDisplayManager.assertResult;
const assertCode = ErrorDisplayManager.assertCode;

const std = @import("std");
const zitrus = @import("zitrus");

const hardware = zitrus.hardware;

const horizon = zitrus.horizon;
const ServiceManager = horizon.ServiceManager;
const ErrorDisplayManager = horizon.ErrorDisplayManager;

const Session = horizon.Session;
const Code = horizon.result.Code;

const Ps9 = horizon.services.pxi.Process9;
const FsUser = horizon.services.fs.User;
const McuPls = horizon.services.mcu.Platform;
const Ps = horizon.services.Ps;
