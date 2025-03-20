package oidc.qr;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static oidc.qr.QRGenerator.IMAGE_SIZE;
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
        assertEquals(IMAGE_SIZE, width);
        assertEquals(IMAGE_SIZE, height);

        Map<DecodeHintType, List<BarcodeFormat>> hints = Map.of(DecodeHintType.POSSIBLE_FORMATS, List.of(BarcodeFormat.QR_CODE));
        Result result = new MultiFormatReader().decode(binaryBitmap, hints);
        assertEquals(BarcodeFormat.QR_CODE, result.getBarcodeFormat());
        assertEquals(url, result.getText());
    }
}