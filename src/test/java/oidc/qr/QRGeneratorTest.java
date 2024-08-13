package oidc.qr;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class QRGeneratorTest {

    @SneakyThrows
    @Test
    void qrCode() {
        String url = "https://surf.nl";
        QRCode qrCode = QRGenerator.qrCode(url);
        assertEquals(url, qrCode.getUrl());
        //Because we can
        byte[] decoded = Base64.getDecoder().decode(qrCode.getImage());
        BinaryBitmap binaryBitmap = new BinaryBitmap(
                new HybridBinarizer(new BufferedImageLuminanceSource(ImageIO.read(new ByteArrayInputStream(decoded)))));
        int height = binaryBitmap.getHeight();
        int width = binaryBitmap.getWidth();
        assertEquals(400, width);
        assertEquals(400, height);

        Result result = new MultiFormatReader().decode(binaryBitmap);
        assertEquals(url, result.getText());
    }
}