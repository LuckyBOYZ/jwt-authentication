package pl.lukaszsuma.jwtauthentication.employees;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/hello")
record EmployeeController(ObservationRegistry observationRegistry) {

    @GetMapping
    public ResponseEntity<String> getEmployees() {
        return Observation
                .createNotStarted("getEmployees", this.observationRegistry)
                .observe(() -> ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT).location(URI.create("http://localhost:8080/api/v1/hello/jol")).build());
    }

    @GetMapping("/jol")
    public ResponseEntity<String> elo(HttpServletRequest request) {
        return ResponseEntity.ok("jol z redirectu!");
    }
}
