--[[
email_auth.lua — Modulo runtime do Nakama pro Verc.

Implementa confirmacao de email no cadastro + recuperacao de senha, via codigo
de 6 digitos enviado por email (provedor: Resend).

Por que server-side: a API key do Resend NAO pode ir pro client (decompilavel),
e a validacao de codigo / troca de senha precisa ser autoritativa no servidor.

RPCs registrados:
  verc_request_confirmation   (autenticado)      -> gera+envia codigo de confirmacao
  verc_confirm_email          (autenticado)      -> valida codigo, marca email_confirmed=true
  verc_request_password_reset (sem sessao/http_key) -> gera+envia codigo de reset
  verc_reset_password         (sem sessao/http_key) -> valida codigo + troca a senha

Env (config runtime.env, vindo de var do Railway):
  RESEND_API_KEY  (obrigatorio)
  RESEND_FROM     (ex: "Verc <no-reply@seudominio>"; fallback onboarding@resend.dev)

Storage:
  collection "email_auth"  key=<user_id>           -> { code, kind, expires, attempts }
  collection "email_index" key=<email_lowercase>   -> { user_id }   (system-owned)
]]

local nk = require("nakama")

local SYSTEM_USER = "00000000-0000-0000-0000-000000000000"
local CODE_TTL_SEC = 900          -- 15 min
local MAX_ATTEMPTS = 5
local COLL_CODE = "email_auth"
local COLL_INDEX = "email_index"

-- ---------- helpers ----------

local function now_sec()
	return math.floor(nk.time() / 1000)
end

local function gen_code()
	-- 6 digitos, seed misturando tempo + uuid pra variar entre chamadas
	local seed = nk.time()
	local uuid = nk.uuid_v4()
	for i = 1, #uuid do
		seed = seed + string.byte(uuid, i)
	end
	math.randomseed(seed)
	return string.format("%06d", math.random(0, 999999))
end

local function norm_email(email)
	return string.lower((email or ""):gsub("%s+", ""))
end

local function send_email(env, to_email, subject, html)
	local key = env["RESEND_API_KEY"]
	if not key or key == "" then
		nk.logger_error("email_auth: RESEND_API_KEY ausente")
		return false, "email_not_configured"
	end
	local from = env["RESEND_FROM"]
	if not from or from == "" then
		from = "Verc <onboarding@resend.dev>"
	end
	local headers = {
		["Authorization"] = "Bearer " .. key,
		["Content-Type"] = "application/json",
	}
	local body = nk.json_encode({
		from = from,
		to = { to_email },
		subject = subject,
		html = html,
	})
	local ok, code, _, resp = pcall(nk.http_request, "https://api.resend.com/emails", "POST", headers, body)
	if not ok then
		nk.logger_error(string.format("email_auth: http_request falhou: %q", tostring(code)))
		return false, "email_send_failed"
	end
	if code < 200 or code >= 300 then
		nk.logger_error(string.format("email_auth: Resend HTTP %d: %s", code, tostring(resp)))
		return false, "email_send_failed"
	end
	return true
end

local function code_email_html(code, is_reset)
	local title = is_reset and "Recuperacao de senha — Verc" or "Confirme seu email — Verc"
	local intro = is_reset
		and "Voce pediu pra redefinir sua senha na Torre Verc. Use o codigo abaixo:"
		or "Bem-vindo a Torre Verc! Confirme seu email com o codigo abaixo:"
	return string.format([[
<div style="font-family:system-ui,Arial,sans-serif;max-width:480px;margin:0 auto;color:#1a1730">
  <h2 style="color:#6a4fb5">%s</h2>
  <p>%s</p>
  <div style="font-size:34px;letter-spacing:10px;font-weight:bold;background:#f0ecff;color:#3a2a7a;padding:18px;text-align:center;border-radius:10px">%s</div>
  <p style="color:#777;font-size:13px">O codigo expira em 15 minutos. Se nao foi voce, ignore este email.</p>
</div>]], title, intro, code)
end

local function write_code(user_id, code, kind)
	nk.storage_write({{
		collection = COLL_CODE,
		key = user_id,
		user_id = SYSTEM_USER,
		value = { code = code, kind = kind, expires = now_sec() + CODE_TTL_SEC, attempts = 0 },
		permission_read = 0,
		permission_write = 0,
	}})
end

local function read_code(user_id)
	local objs = nk.storage_read({{ collection = COLL_CODE, key = user_id, user_id = SYSTEM_USER }})
	if objs and #objs > 0 then
		return objs[1].value
	end
	return nil
end

local function delete_code(user_id)
	pcall(nk.storage_delete, {{ collection = COLL_CODE, key = user_id, user_id = SYSTEM_USER }})
end

local function index_email(email, user_id)
	nk.storage_write({{
		collection = COLL_INDEX,
		key = norm_email(email),
		user_id = SYSTEM_USER,
		value = { user_id = user_id },
		permission_read = 0,
		permission_write = 0,
	}})
end

local function lookup_user_by_email(email)
	local objs = nk.storage_read({{ collection = COLL_INDEX, key = norm_email(email), user_id = SYSTEM_USER }})
	if objs and #objs > 0 then
		return objs[1].value.user_id
	end
	return nil
end

local function set_confirmed(user_id)
	local account = nk.account_get_id(user_id)
	local meta = account.user.metadata or {}
	meta.email_confirmed = true
	nk.account_update_id(user_id, meta)
end

-- ---------- RPC: pedir codigo de confirmacao (autenticado) ----------

local function rpc_request_confirmation(context, _payload)
	if not context.user_id or context.user_id == "" then
		return nk.json_encode({ ok = false, error = "no_session" })
	end
	local account = nk.account_get_id(context.user_id)
	local email = account.email
	if not email or email == "" then
		return nk.json_encode({ ok = false, error = "no_email" })
	end
	-- ja confirmado? nada a fazer
	local meta = account.user.metadata or {}
	if meta.email_confirmed == true then
		return nk.json_encode({ ok = true, already = true })
	end
	index_email(email, context.user_id)
	local code = gen_code()
	write_code(context.user_id, code, "confirm")
	local sent, err = send_email(context.env, email, "Seu codigo Verc", code_email_html(code, false))
	if not sent then
		return nk.json_encode({ ok = false, error = err })
	end
	return nk.json_encode({ ok = true })
end

-- ---------- RPC: confirmar email (autenticado) ----------

local function rpc_confirm_email(context, payload)
	if not context.user_id or context.user_id == "" then
		return nk.json_encode({ ok = false, error = "no_session" })
	end
	local input = (payload and payload ~= "") and nk.json_decode(payload) or {}
	local code = tostring(input.code or "")
	local stored = read_code(context.user_id)
	if not stored or stored.kind ~= "confirm" then
		return nk.json_encode({ ok = false, error = "no_code" })
	end
	if now_sec() > (stored.expires or 0) then
		delete_code(context.user_id)
		return nk.json_encode({ ok = false, error = "expired" })
	end
	if (stored.attempts or 0) >= MAX_ATTEMPTS then
		delete_code(context.user_id)
		return nk.json_encode({ ok = false, error = "too_many" })
	end
	if code ~= tostring(stored.code) then
		stored.attempts = (stored.attempts or 0) + 1
		nk.storage_write({{ collection = COLL_CODE, key = context.user_id, user_id = SYSTEM_USER,
			value = stored, permission_read = 0, permission_write = 0 }})
		return nk.json_encode({ ok = false, error = "wrong_code" })
	end
	set_confirmed(context.user_id)
	delete_code(context.user_id)
	return nk.json_encode({ ok = true })
end

-- ---------- RPC: pedir reset de senha (sem sessao, via http_key) ----------

local function rpc_request_password_reset(_context, payload)
	local input = (payload and payload ~= "") and nk.json_decode(payload) or {}
	local email = norm_email(input.email)
	-- resposta sempre ok (nao vaza se o email existe)
	if email == "" then
		return nk.json_encode({ ok = true })
	end
	local user_id = lookup_user_by_email(email)
	if not user_id then
		return nk.json_encode({ ok = true })
	end
	local code = gen_code()
	write_code(user_id, code, "reset")
	send_email({ RESEND_API_KEY = _context.env["RESEND_API_KEY"], RESEND_FROM = _context.env["RESEND_FROM"] },
		email, "Recuperar senha — Verc", code_email_html(code, true))
	return nk.json_encode({ ok = true })
end

-- ---------- RPC: resetar senha (sem sessao, via http_key) ----------

local function rpc_reset_password(_context, payload)
	local input = (payload and payload ~= "") and nk.json_decode(payload) or {}
	local email = norm_email(input.email)
	local code = tostring(input.code or "")
	local new_password = tostring(input.new_password or "")
	if email == "" or #new_password < 8 then
		return nk.json_encode({ ok = false, error = "invalid_input" })
	end
	local user_id = lookup_user_by_email(email)
	if not user_id then
		return nk.json_encode({ ok = false, error = "wrong_code" })
	end
	local stored = read_code(user_id)
	if not stored or stored.kind ~= "reset" then
		return nk.json_encode({ ok = false, error = "no_code" })
	end
	if now_sec() > (stored.expires or 0) then
		delete_code(user_id)
		return nk.json_encode({ ok = false, error = "expired" })
	end
	if (stored.attempts or 0) >= MAX_ATTEMPTS then
		delete_code(user_id)
		return nk.json_encode({ ok = false, error = "too_many" })
	end
	if code ~= tostring(stored.code) then
		stored.attempts = (stored.attempts or 0) + 1
		nk.storage_write({{ collection = COLL_CODE, key = user_id, user_id = SYSTEM_USER,
			value = stored, permission_read = 0, permission_write = 0 }})
		return nk.json_encode({ ok = false, error = "wrong_code" })
	end
	-- troca a senha: relink do email com a nova senha
	local ok_unlink = pcall(nk.unlink_email, user_id, email)
	local ok_link = pcall(nk.link_email, user_id, email, new_password)
	if not ok_link then
		nk.logger_error("email_auth: falha ao relincar email no reset de " .. email)
		return nk.json_encode({ ok = false, error = "reset_failed" })
	end
	delete_code(user_id)
	return nk.json_encode({ ok = true, unlinked = ok_unlink })
end

-- ---------- registro ----------

nk.register_rpc(rpc_request_confirmation, "verc_request_confirmation")
nk.register_rpc(rpc_confirm_email, "verc_confirm_email")
nk.register_rpc(rpc_request_password_reset, "verc_request_password_reset")
nk.register_rpc(rpc_reset_password, "verc_reset_password")

nk.logger_info("email_auth.lua carregado (confirmacao + reset por codigo)")
