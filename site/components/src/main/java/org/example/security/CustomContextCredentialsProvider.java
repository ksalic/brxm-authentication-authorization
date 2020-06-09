package org.example.security;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.jcr.Credentials;
import javax.servlet.http.HttpSession;

import org.example.security.util.UserUtils;
import org.hippoecm.hst.core.request.ContextCredentialsProvider;
import org.hippoecm.hst.core.request.HstRequestContext;
import org.onehippo.forge.security.support.springsecurity.authentication.HippoUser;
import org.springframework.security.core.GrantedAuthority;

/**
 * @version "\$Id$" kenan
 */
public class CustomContextCredentialsProvider implements ContextCredentialsProvider {

    private final Map<String, Credentials> credentialsMap = new HashMap<>();
    private Credentials defaultCredentials;
    private Credentials sitegroupAliveuser;
    private Credentials sitegroupBliveuser;
    private Credentials defaultCredentialsForPreviewMode;
    private Credentials writableCredentials;


    public CustomContextCredentialsProvider(final Credentials defaultCredentials,
                                            final Credentials sitegroupAliveuser,
                                            final Credentials sitegroupBliveuser,

                                            final Credentials defaultCredentialsForPreviewMode,
                                            final Credentials writableCredentials) {
        this.defaultCredentials = defaultCredentials;

        this.sitegroupAliveuser = sitegroupAliveuser;
        this.sitegroupBliveuser = sitegroupBliveuser;


        this.defaultCredentialsForPreviewMode = defaultCredentialsForPreviewMode;
        this.writableCredentials = writableCredentials;

        credentialsMap.put("ROLE_xm.live-documents-a.reader", this.sitegroupAliveuser);
        credentialsMap.put("ROLE_xm.live-documents-b.reader", this.sitegroupBliveuser);

        credentialsMap.put("admin", this.defaultCredentials);
    }

    public Credentials getDefaultCredentials(HstRequestContext requestContext) {
        if (defaultCredentialsForPreviewMode != null && requestContext.isPreview()) {
            return defaultCredentialsForPreviewMode;
        }
        final HttpSession session = requestContext.getServletRequest().getSession(false);
        if (session == null || requestContext.getServletRequest().getUserPrincipal() == null) {
            return defaultCredentials;
        }

        final HippoUser user = UserUtils.getUser(requestContext);
        Optional<GrantedAuthority> liveuser = user.getAuthorities().stream().filter(grantedAuthority -> grantedAuthority.getAuthority().contains("xm.live-documents")).findFirst();
        if (liveuser.isPresent() && credentialsMap.containsKey(liveuser.get().getAuthority())) {
            return credentialsMap.get(liveuser.get().getAuthority());
        }
        throw new CustomSessionPoolException("not allowed to access the credentials map with group " + user.getUsername());
    }

    public Credentials getWritableCredentials(HstRequestContext requestContext) {
        return writableCredentials;
    }
}