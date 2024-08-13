package oidc.qr;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class QRCode {

    private String url;
    private String image;
}
