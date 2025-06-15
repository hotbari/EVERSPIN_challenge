package com.everspin.challenge.servlet;

import java.io.IOException;
import java.util.Random;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONObject;

@WebServlet("/step8")
public class Step8Servlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Random random = new Random();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String puzzleAnswer = request.getHeader("x-puzzle-answer");
        
        if (puzzleAnswer == null) {
            // 첫 번째 요청: 퍼즐 생성
            long timeFactor = System.currentTimeMillis() % 1000;
            int ipFactor = request.getRemoteAddr().hashCode() % 1000;
            int randomFactor = random.nextInt(1000);
            
            JSONObject json = new JSONObject();
            json.put("status", "puzzle");
            json.put("timeFactor", timeFactor);
            json.put("ipFactor", ipFactor);
            json.put("randomFactor", randomFactor);
            
            response.getWriter().write(json.toString());
        } else {
            // 두 번째 요청: 퍼즐 검증
            try {
                int answer = Integer.parseInt(puzzleAnswer);
                long timeFactor = System.currentTimeMillis() % 1000;
                int ipFactor = request.getRemoteAddr().hashCode() % 1000;
                int randomFactor = random.nextInt(1000);
                
                int expectedAnswer = (int)((timeFactor + ipFactor + randomFactor) % 1000);
                
                JSONObject json = new JSONObject();
                if (answer == expectedAnswer) {
                    json.put("status", "success");
                    json.put("msg", "퍼즐을 성공적으로 해결했습니다!");
                } else {
                    json.put("status", "error");
                    json.put("msg", "퍼즐 해결에 실패했습니다.");
                }
                
                response.getWriter().write(json.toString());
            } catch (NumberFormatException e) {
                JSONObject json = new JSONObject();
                json.put("status", "error");
                json.put("msg", "잘못된 퍼즐 답변 형식입니다.");
                response.getWriter().write(json.toString());
            }
        }
    }
} 