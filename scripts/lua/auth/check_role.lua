-- Get JWT token from header Authorization
local auth_header = kong.request.get_header("Authorization")
if not auth_header then
    return kong.response.exit(401, { message = "Missing Authorization header" })
end
-- Get token from "Bearer <token>"
local token = auth_header:match("^Bearer%s+(.+)$")
if not token then
    return kong.response.exit(401, { message = "invalid Token format" })
end
-- Split token into 3 parts: header.payload.signature
local token_parts = {}
for part in token:gmatch("[^.]+") do
    table.insert(token_parts, part)
end

if #token_parts ~= 3 then
    return kong.response.exit(401, { message = "invalid JWT token structure" })
end

-- decode payload part (middle part of JWT)
local payload_str = ngx.decode_base64(token_parts[2])
if not payload_str then
    return kong.response.exit(401, { message = "failed to decode JWT payload" })
end

-- Extract value "role" from JSON payload
local role = payload_str:match('"role"%s*:%s*"([^"]+)"')
if not role then
    return kong.response.exit(403, { message = "missing role in token" })
end

if role ~= "customer" then
    return kong.response.exit(403, { message = "access Denied: Requires Admin Role" })
end