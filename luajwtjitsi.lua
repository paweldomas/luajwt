local cjson  = require 'cjson'
local base64 = require 'base64'
local digest = require 'openssl.digest'
local hmac   = require 'openssl.hmac'
local pkey   = require 'openssl.pkey'

function safe_require(mod)
  local status, loadedMod = pcall(function() return require(mod) end)
  if status then
    return loadedMod
  else
    return status, loadedMod
  end
end

local bit = safe_require'bit'

local digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }

local tohex = nil

if bit then
  local bit_tohex = bit and bit.tohex or nil
  --fastest in luajit
  tohex = function(s)
    local result = {}
    for i = 1, #s do
      local byte = string.byte(s, i)
      table.insert(result, digits[bit.rshift(byte, 4) + 1])
      table.insert(result, digits[bit.band(byte, 15)+ 1])
    end
    return table.concat(result)
  end
elseif _VERSION == 'Lua 5.3' then
  --fastest in lua 5.3
  --compile dynamically to be syntactically compatible with 5.1
  loader, err = load[[
    local digits = ...
    return function(s)
      local result = ""
      for i = 1, #s do
        local byte = string.byte(s, i)
        result = result..(digits[(byte >> 4) + 1])..(digits[(byte&15)+ 1])
      end
      return result
    end
  ]]
  tohex = loader(digits)
else
  --fastest in lua 5.1
  tohex = function(s)
    local result = ""
    for i = 1, #s do
      local byte = string.byte(s, i)
      result = result..(digits[math.floor(byte / 16) + 1])..(digits[(byte % 16) + 1])
    end
    return result
  end
end

local function signRS(data, key, algo)
    local ok, result = pcall(function()
      return pkey.new(key):sign(digest.new(algo):update(data))
    end)
    if not ok then return nil, result end
    return result
end

local function verifyRS(data, signature, key, algo)
    local ok, result = pcall(function()
      return pkey.new(key):verify(signature, digest.new(algo):update(data))
    end)
    if not ok then return nil, result end
    return result
end

local alg_sign = {
	['HS256'] = function(data, key) return tohex(hmac.new(key, 'sha256'):final (data)) end,
	['HS384'] = function(data, key) return tohex(hmac.new(key, 'sha384'):final (data)) end,
	['HS512'] = function(data, key) return tohex(hmac.new(key, 'sha512'):final (data)) end,
	['RS256'] = function(data, key) return signRS(data, key, 'sha256') end,
	['RS384'] = function(data, key) return signRS(data, key, 'sha384') end,
	['RS512'] = function(data, key) return signRS(data, key, 'sha512') end
}

local alg_verify = {
	['HS256'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha256'):final (data)) end,
	['HS384'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha384'):final (data)) end,
	['HS512'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha512'):final (data)) end,
	['RS256'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha256') end,
	['RS384'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha384') end,
	['RS512'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha512') end
}

local function b64_encode(input)
	local result = base64.encode(input)

	result = result:gsub('+','-'):gsub('/','_'):gsub('=','')

	return result
end

local function b64_decode(input)
--	input = input:gsub('\n', ''):gsub(' ', '')

	local reminder = #input % 4

	if reminder > 0 then
		local padlen = 4 - reminder
		input = input .. string.rep('=', padlen)
	end

	input = input:gsub('-','+'):gsub('_','/')

	return base64.decode(input)
end

local function tokenize(str, div, len)
	local result, pos = {}, 0

	for st, sp in function() return str:find(div, pos, true) end do

		result[#result + 1] = str:sub(pos, st-1)
		pos = sp + 1

		len = len - 1

		if len <= 1 then
			break
		end
	end

	result[#result + 1] = str:sub(pos)

	return result
end

local M = {}

function M.encode(data, key, alg)
	if type(data) ~= 'table' then return nil, "Argument #1 must be table" end
	if type(key) ~= 'string' then return nil, "Argument #2 must be string" end

	alg = alg or "HS256"

	if not alg_sign[alg] then
		return nil, "Algorithm not supported"
	end

	local header = { typ='JWT', alg=alg }

	local segments = {
		b64_encode(cjson.encode(header)),
		b64_encode(cjson.encode(data))
	}

	local signing_input = table.concat(segments, ".")
	local signature, error = alg_sign[alg](signing_input, key)
	if signature == nil then
		return nil, error
	end

	segments[#segments+1] = b64_encode(signature)

	return table.concat(segments, ".")
end

function M.decode(data, key, verify)
	if key and verify == nil then verify = true end
	if type(data) ~= 'string' then return nil, "Argument #1 must be string" end
	if verify and type(key) ~= 'string' then return nil, "Argument #2 must be string" end

	local token = tokenize(data, '.', 3)

	if #token ~= 3 then
		return nil, "Invalid token"
	end

	local headerb64, bodyb64, sigb64 = token[1], token[2], token[3]

	local ok, header, body, sig = pcall(function ()

		return	cjson.decode(b64_decode(headerb64)),
			cjson.decode(b64_decode(bodyb64)),
			b64_decode(sigb64)
	end)

	if not ok then
		return nil, "Invalid json"
	end

	if verify then

		if not header.typ or (header.typ ~= "JOSE" and header.typ ~= "JWT") then
			return nil, "Invalid typ"
		end

		if not header.alg or type(header.alg) ~= "string" then
			return nil, "Invalid alg"
		end

		if body.exp and type(body.exp) ~= "number" then
			return nil, "exp must be number"
		end

		if body.nbf and type(body.nbf) ~= "number" then
			return nil, "nbf must be number"
		end

		if not alg_verify[header.alg] then
			return nil, "Algorithm not supported"
		end

		local verify_result, error
			= alg_verify[header.alg](headerb64 .. "." .. bodyb64, sig, key);
		if verify_result == nil then
			return nil, error
		elseif verify_result == false then
			return nil, "Invalid signature"
		end

		if body.exp and os.time() >= body.exp then
			return nil, "Not acceptable by exp"
		end

		if body.nbf and os.time() < body.nbf then
			return nil, "Not acceptable by nbf"
		end
	end

	return body
end

return M
