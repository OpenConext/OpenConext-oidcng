package oidc.log;


import oidc.model.User;
import org.slf4j.MDC;
import org.slf4j.spi.MDCAdapter;
import org.springframework.util.Assert;

public class MDCContext {

    public static void mdcContext(String... args) {
        mdcContext(null, args);
    }

    public static void mdcContext(User user, String... args) {
        Assert.isTrue(args.length % 2 == 0, "contextMap requires an even number of arguments");
        MDCAdapter mdcAdapter = MDC.getMDCAdapter();
        for (int i = 0; i < args.length - 1; i += 2) {
            mdcAdapter.put(args[i], args[i + 1]);
        }
        if (MDC.get("user_id") == null && user != null) {
            mdcAdapter.put("user_id", user.getId());
            mdcAdapter.put("user_name_id", user.getUnspecifiedNameId());
        }
    }


}
