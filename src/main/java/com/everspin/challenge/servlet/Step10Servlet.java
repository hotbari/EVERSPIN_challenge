package com.everspin.challenge.servlet;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONObject;

@WebServlet("/step10")
public class Step10Servlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final ConcurrentHashMap<String, Long> dnaHistory = new ConcurrentHashMap<>();
    private static final long DNA_EXPIRY_TIME = 30000; // 30초

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String dnaHash = request.getHeader("x-dna-hash");
        
        if (dnaHash == null) {
            // 첫 번째 요청: DNA 해시 생성
            try {
                String requestDNA = generateRequestDNA(request);
                String hash = generateHash(requestDNA);
                
                // DNA 해시 저장
                dnaHistory.put(hash, System.currentTimeMillis());
                
                JSONObject json = new JSONObject();
                json.put("status", "dna");
                json.put("hash", hash);
                
                response.getWriter().write(json.toString());
            } catch (NoSuchAlgorithmException e) {
                JSONObject json = new JSONObject();
                json.put("status", "error");
                json.put("msg", "DNA 해시 생성 중 오류가 발생했습니다.");
                response.getWriter().write(json.toString());
            }
        } else {
            // 두 번째 요청: DNA 해시 검증
            try {
                String requestDNA = generateRequestDNA(request);
                String expectedHash = generateHash(requestDNA);
                
                JSONObject json = new JSONObject();
                
                // DNA 해시 검증
                if (!dnaHash.equals(expectedHash)) {
                    json.put("status", "error");
                    json.put("msg", "요청 DNA가 유효하지 않습니다.");
                    response.getWriter().write(json.toString());
                    return;
                }
                
                // DNA 해시 만료 시간 검증
                Long timestamp = dnaHistory.get(dnaHash);
                if (timestamp == null || System.currentTimeMillis() - timestamp > DNA_EXPIRY_TIME) {
                    json.put("status", "error");
                    json.put("msg", "요청 DNA가 만료되었습니다.");
                    response.getWriter().write(json.toString());
                    return;
                }
                
                // DNA 해시 재사용 방지
                dnaHistory.remove(dnaHash);
                
                json.put("status", "success");
                json.put("msg", "요청 DNA가 유효합니다!");
                response.getWriter().write(json.toString());
                
            } catch (NoSuchAlgorithmException e) {
                JSONObject json = new JSONObject();
                json.put("status", "error");
                json.put("msg", "DNA 해시 검증 중 오류가 발생했습니다.");
                response.getWriter().write(json.toString());
            }
        }
    }
    
    private String generateRequestDNA(HttpServletRequest request) {
        StringBuilder dna = new StringBuilder();
        dna.append(request.getRemoteAddr());
        dna.append(request.getHeader("User-Agent"));
        dna.append(request.getHeader("Accept-Language"));
        dna.append(request.getHeader("Accept-Encoding"));
        dna.append(request.getHeader("Connection"));
        dna.append(System.currentTimeMillis() / 1000); // 초 단위로 반올림
        return dna.toString();
    }
    
    private String generateHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
} 