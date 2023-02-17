import com.b2a.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class TestJwtUtil {
    private static final Logger logger = LogManager.getLogger();

    @Test
    public void testGenerateAndDecode() {
        String jwtId = "ID0001";
        String jwtIssuer = "B2A";
        String jwtSubject = "canhnd";
        long expTime = 60000; //thời gian hiệu lực: 1 phút

        String jwt = JwtUtil.generateJWT(
                jwtId,
                jwtIssuer,
                jwtSubject,
                expTime // used to calculate expiration (claim = exp)
        );

        logger.info("generated jwt = \"" + jwt + "\"");

        Claims claims = JwtUtil.decodeJWT(jwt);

        logger.info("claims = " + claims.toString());

        assertEquals(jwtId, claims.getId());
        assertEquals(jwtIssuer, claims.getIssuer());
        assertEquals(jwtSubject, claims.getSubject());
    }

    @Test(expected = MalformedJwtException.class)
    public void testInvalidJwt() {
        String invalidJwt = "day la mot jwt sai";

        // This will fail with expected exception listed above
        JwtUtil.decodeJWT(invalidJwt);
    }

    @Test(expected = SignatureException.class)
    public void testChangedJWT() {
        String jwtId = "ID0001";
        String jwtIssuer = "B2A";
        String jwtSubject = "canhnd";
        long expTime = 60000; //thời gian hiệu lực: 1 phút

        String jwt = JwtUtil.generateJWT(
                jwtId,
                jwtIssuer,
                jwtSubject,
                expTime
        );

        logger.info("jwt = \"" + jwt + "\"");

        // thay đổi nội dung của JWT vừa được tạo ra -> invalid JWT
        StringBuilder changedJwt = new StringBuilder(jwt);
        changedJwt.setCharAt(22, 'G');

        logger.info("ChangedJwt = \"" + changedJwt + "\"");

        assertNotEquals(jwt, changedJwt);

        JwtUtil.decodeJWT(changedJwt.toString());
    }
}
