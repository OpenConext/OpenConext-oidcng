package oidc.api;

import oidc.secure.KeyRollover;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    private static final Log LOG = LogFactory.getLog(AdminController.class);

    @Autowired
    private KeyRollover keyRollover;

    @GetMapping("manage/force-signing-key-rollover")
    @PreAuthorize("hasRole('ROLE_manage')")
    public ResponseEntity<Void> rolloverSigningKey(Authentication authentication) {
        String name = authentication.getName();

        LOG.info("Starting a forced signing key rollover by: " + name);

        keyRollover.doSigningKeyRollover();

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("manage/force-symmetric-key-rollover")
    @PreAuthorize("hasRole('ROLE_manage')")
    public ResponseEntity<Void> rolloverSymmetricKey(Authentication authentication) {
        String name = authentication.getName();

        LOG.info("Starting a forced symmetric key rollover by: " + name);

        keyRollover.doSymmetricKeyRollover();

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
