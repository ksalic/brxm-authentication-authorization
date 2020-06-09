package org.example.security.util;

import java.security.Principal;

import org.hippoecm.hst.container.RequestContextProvider;
import org.hippoecm.hst.core.request.HstRequestContext;
import org.onehippo.forge.security.support.springsecurity.authentication.HippoUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * @version "\$Id$" kenan
 */
public final class UserUtils {


    private static final Logger LOG = LoggerFactory.getLogger(UserUtils.class);

    private UserUtils() {
    }

    public static HippoUser getUser() {
        final HstRequestContext context = RequestContextProvider.get();
        return getUser(context);
    }

    public static HippoUser getUser(final HstRequestContext context) {
        try {
            if (context.getServletRequest().getUserPrincipal() != null) {
                final Principal userPrincipal = context.getServletRequest().getUserPrincipal();
                if (userPrincipal instanceof UsernamePasswordAuthenticationToken && ((UsernamePasswordAuthenticationToken)userPrincipal).getPrincipal() instanceof HippoUser) {
                    return (HippoUser)((UsernamePasswordAuthenticationToken)context.getServletRequest().getUserPrincipal()).getPrincipal();
                }

            }
        } catch (Exception e) {
            LOG.error("Error while trying to retrieve the correct user from the request", e);
        }
        return null;
    }

}