using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace NateGZ_Blazor.Client
{
    public class CustomUserFactory : AccountClaimsPrincipalFactory<RemoteUserAccount>
    {
        public CustomUserFactory(IAccessTokenProviderAccessor accessor) : base(accessor)
        {

        }

        public async override ValueTask<ClaimsPrincipal> CreateUserAsync(
       RemoteUserAccount account,
       RemoteAuthenticationUserOptions options)
        {
            var initialUser = await base.CreateUserAsync(account, options);

            if (initialUser.Identity.IsAuthenticated)
            {
                var identity = (ClaimsIdentity)initialUser.Identity;
                var roleClaims = identity.FindAll(identity.RoleClaimType);
                
                if (roleClaims !=null && roleClaims.Any())
                {
                    foreach (var existingClaim in roleClaims)
                    {
                        identity.RemoveClaim(existingClaim);
                    }

                    var rolesElem = account.AdditionalProperties[identity.RoleClaimType];
                    if(rolesElem is JsonElement roles)
                    {
                        if(roles.ValueKind == JsonValueKind.Array)
                        {
                            foreach(var role in roles.EnumerateArray())
                            {
                                identity.AddClaim(new Claim(options.RoleClaim, role.GetString()));
                            }
                        }
                        else
                        {
                            identity.AddClaim(new Claim(options.RoleClaim, roles.GetString()));
                        }
                    }
                }

            }


            return initialUser;
        }
    }
}
