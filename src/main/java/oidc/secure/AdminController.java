package oidc.secure;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    private static final Log LOG = LogFactory.getLog(AdminController.class);

    @Autowired
    private KeyRollover keyRollover;


    @GetMapping("manage/force-key-rollover")
    public ResponseEntity<Void> rollover(Authentication authentication) {
        String name = authentication.getName();

        LOG.info("Starting a forced key rollover from: " + name);

        keyRollover.doRollover();

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}
