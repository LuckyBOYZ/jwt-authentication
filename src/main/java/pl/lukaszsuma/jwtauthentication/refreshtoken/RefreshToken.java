package pl.lukaszsuma.jwtauthentication.refreshtoken;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "refreshtoken", schema = "authentication")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @Column(name = "refreshtoken_id", nullable = false, length = 36)
    private String id;

    @Column(nullable = false)
    private long expiryTime;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(columnDefinition = "tinyint(1)")
    private boolean enable;
}
