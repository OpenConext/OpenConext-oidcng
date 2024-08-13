package oidc.qr;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

public class QRGenerator {

    private static final int IMAGE_SIZE = 400;

    private QRGenerator() {
    }

    @SneakyThrows
    public static QRCode qrCode(String url) {
        BitMatrix matrix = new MultiFormatWriter().encode(url, BarcodeFormat.QR_CODE, IMAGE_SIZE, IMAGE_SIZE);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "png", bos);
        //<img src="data:image/png;base64,iVBORw0KGgoA....>
        String image = Base64.getEncoder().encodeToString(bos.toByteArray()); // base64 encode
        return new QRCode(url, image);
    }
}
