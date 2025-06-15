package com.everspin.challenge.servlet;

import java.io.IOException;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONObject;

@WebServlet("/step5")
public class Step5Servlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final ConcurrentHashMap<String, Long> nonceHistory = new ConcurrentHashMap<>();
    private static final long NONCE_EXPIRY_TIME = 30000; // 30초
    private Random random = new Random();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String signature = request.getHeader("x-request-signature");
        String timestamp = request.getHeader("x-request-timestamp");
        String nonce = request.getHeader("x-request-nonce");
        
        if (signature == null || timestamp == null || nonce == null) {
            // 첫 번째 요청: 시그니처 생성 정보 제공
            String newNonce = generateNonce();
            nonceHistory.put(newNonce, System.currentTimeMillis());
            
            JSONObject json = new JSONObject();
            json.put("status", "signature");
            json.put("timestamp", System.currentTimeMillis());
            json.put("nonce", newNonce);
            
            response.getWriter().write(json.toString());
        } else {
            // 두 번째 요청: 시그니처 검증
            try {
                // nonce 만료 시간 검증
                Long nonceTimestamp = nonceHistory.get(nonce);
                if (nonceTimestamp == null || System.currentTimeMillis() - nonceTimestamp > NONCE_EXPIRY_TIME) {
                    JSONObject json = new JSONObject();
                    json.put("status", "error");
                    json.put("msg", "nonce가 만료되었습니다.");
                    response.getWriter().write(json.toString());
                    return;
                }
                
                // nonce 재사용 방지
                nonceHistory.remove(nonce);
                
                // 시그니처 검증
                String username = request.getParameter("username");
                String expectedSignature = generateSignature(username, timestamp, nonce);
                
                JSONObject json = new JSONObject();
                if (signature.equals(expectedSignature)) {
                    json.put("status", "success");
                    json.put("msg", "요청 시그니처가 유효합니다!");
                } else {
                    json.put("status", "error");
                    json.put("msg", "요청 시그니처가 유효하지 않습니다.");
                }
                
                response.getWriter().write(json.toString());
            } catch (Exception e) {
                JSONObject json = new JSONObject();
                json.put("status", "error");
                json.put("msg", "시그니처 검증 중 오류가 발생했습니다.");
                response.getWriter().write(json.toString());
            }
        }
    }
    
    private String generateNonce() {
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }
    
    private String generateSignature(String username, String timestamp, String nonce) {
        String data = username + timestamp + nonce;
        return Base64.getEncoder().encodeToString(data.getBytes());
    }
} 