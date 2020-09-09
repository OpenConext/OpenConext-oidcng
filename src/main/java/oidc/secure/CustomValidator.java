package oidc.secure;

import org.joda.time.DateTime;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CustomValidator {

    private Map<String, List<? extends Serializable>> userAttributes;

    public CustomValidator() {
        userAttributes = new HashMap<>();
        List<String> strings = new ArrayList();
        userAttributes.put("aa", strings);
    }

    //extends DefaultValidator {
//
//    public CustomValidator(SpringSecuritySaml implementation) {
//        super(implementation);
//    }
//
//    @Override
//    public boolean isDateTimeSkewValid(int skewMillis, int forwardMillis, DateTime time) {
//        if (forwardMillis == 0) {
//            return super.isDateTimeSkewValid(skewMillis, forwardMillis, time);
//        }
//        return true;
//    }
}
