package com.everspin.challenge.servlet;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONObject;

@WebServlet("/step6")
public class Step6Servlet extends HttpServlet {
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
        String challenge = request.getHeader("x-request-challenge");
        
        if (signature == null || timestamp == null || nonce == null || challenge == null) {
            // 첫 번째 요청: 시그니처 생성 정보 제공
            String newNonce = generateNonce();
            String newChallenge = generateChallenge();
            nonceHistory.put(newNonce, System.currentTimeMillis());
            
            JSONObject json = new JSONObject();
            json.put("status", "signature");
            json.put("timestamp", System.currentTimeMillis());
            json.put("nonce", newNonce);
            json.put("challenge", newChallenge);
            
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
                String expectedSignature = generateSignature(username, timestamp, nonce, challenge);
                
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
    
    private String generateChallenge() {
        try {
            byte[] randomBytes = new byte[32];
            random.nextBytes(randomBytes);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(randomBytes);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return Base64.getEncoder().encodeToString(random.nextBytes(32));
        }
    }
    
    private String generateSignature(String username, String timestamp, String nonce, String challenge) {
        String data = username + timestamp + nonce + challenge;
        return Base64.getEncoder().encodeToString(data.getBytes());
    }
} 