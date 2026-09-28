package ra.demo.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import ra.demo.config.RouteValidator;
import ra.demo.jwt.JwtUtils;
import reactor.core.publisher.Mono;

import java.util.List;

@Component // Đánh dấu đây là một Spring Bean
@RequiredArgsConstructor // Lombok tự động tạo Constructor để tiêm (Inject) các biến final (routeValidator, jwtUtils)
@Slf4j // Lombok hỗ trợ ghi log (sử dụng biến 'log')
public class GatewayFilter implements GlobalFilter, Ordered {

    private final RouteValidator routeValidator;
    private final JwtUtils jwtUtils;
    private final ReactiveStringRedisTemplate reactiveStringRedisTemplate;

    /**
     * Phương thức xử lý chính của Filter cho mọi Request đi qua Gateway
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // BƯỚC 1: Kiểm tra xem Request này có thuộc nhóm API CẦN BẢO MẬT hay không
        if (routeValidator.isSecured.test(request)) {

            // 1.1 Trích xuất Header 'Authorization' từ Request gửi lên
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // 1.2 Kiểm tra sự tồn tại của Header Authorization
            if (authHeader == null || authHeader.isEmpty()) {
                log.error("Missing Authorization Header for secure path: {}", request.getURI().getPath());
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Missing authorization header");
            }

            // 1.3 Kiểm tra định dạng chuẩn của Token (Bắt buộc phải bắt đầu bằng "Bearer ")
            if (!authHeader.startsWith("Bearer ")) {
                log.error("Không đúng định dạng chuỗi jwt token: {}", authHeader);
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid authorization header format");
            }

            // 1.4 Lấy ra chuỗi JWT Token nguyên bản (xóa khoảng trắng/xuống dòng thừa)
            String token = authHeader.substring(7);

            // ----------------------------------------------------------------------------------
            // BỔ SUNG BƯỚC 1.5: KIỂM TRA REDIS BLACKLIST (BÀI TẬP 5)
            // ----------------------------------------------------------------------------------
            String jti = jwtUtils.extractJti(token); // Cần thêm hàm extractJti trong JwtUtils
            if (jti != null) {
                String redisKey = "blacklist:" + jti;

                return reactiveStringRedisTemplate.hasKey(redisKey)
                        .flatMap(isBlacklisted -> {
                            if (Boolean.TRUE.equals(isBlacklisted)) {
                                log.warn("Gateway CHẶN Request! Token (JTI: {}) đã bị Revoke/Logout", jti);
                                return onError(exchange, HttpStatus.UNAUTHORIZED, "Token has been revoked/logged out");
                            }

                            // Nếu KHÔNG bị Blacklist -> Tiếp tục luồng kiểm tra phía dưới
                            return continueProcessing(exchange, chain, request, token);
                        });
            }

            return continueProcessing(exchange, chain, request, token);
        }

        // Nếu API KHÔNG CẦN BẢO MẬT -> Cho qua thẳng
        return chain.filter(exchange);
    }

    /**
     * Hàm phụ trợ thực hiện BƯỚC 2, 3, 4, 5 tiếp nối sau khi check Blacklist thành công
     */
    private Mono<Void> continueProcessing(ServerWebExchange exchange, GatewayFilterChain chain, ServerHttpRequest request, String token) {
        // BƯỚC 2: XÁC THỰC TOKEN
        if (!jwtUtils.validateToken(token)) {
            log.error("Invalid/Expired JWT token");
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }

        // BƯỚC 3: TRÍCH XUẤT THÔNG TIN TỪ TOKEN
        List<String> roles = jwtUtils.extractRoles(token);
        String username = jwtUtils.extractUsername(token);
        log.info("Request by user: {}, roles: {}", username, roles);

        // BƯỚC 4: PHÂN QUYỀN TRUY CẬP
        String path = request.getURI().getPath();
        String method = request.getMethod().name();

        if (!routeValidator.isAuthorized(path, method, roles)) {
            log.warn("User {} unauthorized to call API {} {}", username, method, path);
            return onError(exchange, HttpStatus.FORBIDDEN, "Access denied: Unauthorized access");
        }

        // BƯỚC 5: ĐÁNH DẤU & CHUYỂN TIẾP
        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Id", username)
                .header("X-User-Role", (roles != null && !roles.isEmpty()) ? String.join(",", roles) : "")
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    /**
     * Hàm hỗ trợ ngắt luồng và trả về Response lỗi cho Client (401 hoặc 403)
     */
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus); // Thiết lập HTTP Status Code (401 Unauthorized / 403 Forbidden)
        return response.setComplete();     // Hoàn tất và gửi phản hồi về ngay lập tức
    }

    /**
     * Thiết lập thứ tự ưu tiên của Filter
     * Trả về -1 để đảm bảo Filter này chạy ĐẦU TIÊN trong chuỗi Global Filters của Spring Cloud Gateway
     */
    @Override
    public int getOrder() {
        return -1;
    }
}