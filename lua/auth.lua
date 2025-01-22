function authValidate(location)
    local req = ctx.load();
    local requested_group = getAuthGroup(req)
    -- print('Requested Group: ' .. requested_group); -- DEBUG
    local jwt_groups = req:headers('JWT-Groups') -- propogated from JWT token
    -- TODO: for some services we may conditionally propagate JWT-Groups as X-Auth-Groups header
    -- print('JWT Groups:' .. tostring(jwt_groups)); -- DEBUG
    local authorized_groups = split_to_dict(jwt_groups) -- auth groups are comma separated
    if authorized_groups[requested_group] then
        req:headers('X-Auth-Group', requested_group) -- Set requested group as the authorized
    else
        custom_error('Requested group is not authorized', 401)
        return false;
    end
    local account_project, role = requested_group:match("^(.*)[./-]([^./-]+)$")
    local account, project = account_project:match("^([^./-]+)[./-]?(.*)$")
    print('Auth user:[' ..  req:headers('X-Auth-User') .. '] as account:[' .. tostring(account) .. '] in project:[' .. tostring(project) .. '] with role:[' .. tostring(role) .. ']');
    req:headers('X-Auth-Account', account)
    req:headers('X-Auth-Project', project)
    req:headers('X-Auth-Role', role)
    verifyLocation(req, account, location)
end

function verifyLocation(req, account, location)
    -- print('Check if account [' .. tostring(account) .. '] is authorized to access location [' .. tostring(location) .. ']') -- DEBUG
    local jwt_accounts = req:headers('JWT-Accounts')
    if jwt_accounts == "" or location == "" then
        -- if there is not 'external' claim from JWT token with info about authorized locations for each organization accounts
        print('Warning: Location is not specified or JWT.external claim is not provided, skipping location authorization check')
        return true;
    end
    local authorized_accounts = json_parse(jwt_accounts)
    local account_config = authorized_accounts[account]
    if not account_config then -- strange situation, should not happen
        custom_error('Requested account is not found among authorized accounts', 401)
        return false;
    end
    for _, authorized_location in pairs(account_config['locations']) do
        print('Authorized Location: ' .. tostring(authorized_location))
        if authorized_location == location then
            print('Account is authorized to use this location')
            return true;
        end
    end
    custom_error('Requested account is not authorized to use this location', 401)
    return false;
end


function getAuthGroup(req)
    local group = req:headers('X-Auth-Group')
    if group == "" then
        local account = req:headers('X-Auth-Account')
        local role = req:headers('X-Auth-Role')
        -- For backward compatibility
        if account == "" then
            account = req:headers('X-Icdc-Account')
            if not account == "" then
                print('Warning: X-Icdc-Account header is deprecated, please use X-Auth-Group instead')
            end
        else
            print('Warning: X-Auth-Account header is deprecated, please use X-Auth-Group instead')
        end
        if role == "" then
            role = req:headers('X-Icdc-Role')
            if not role == "" then
                print('Warning: X-Icdc-Role header is deprecated, please use X-Auth-Group instead')
            end
        else
            print('Warning: X-Auth-Role header is deprecated, please use X-Auth-Group instead')
        end
        -- For backward compatibility, try using X-Auth-Account and X-Auth-Role
        if account == ""  or role == "" then
            custom_error("X-Auth-Group header is required", 401)
            return false;
        end
        group = account .. '.' .. role
    end
    return group
end

function split_to_dict(str)
    local d = {}
    for part in string.gmatch(str, "([^,]+)") do
      d[part] = true
    end
    return d
end