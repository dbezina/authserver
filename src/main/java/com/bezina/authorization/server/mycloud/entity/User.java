package com.bezina.authorization.server.mycloud.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


@Entity
@Data
@Table(name = "test_users")
@RequiredArgsConstructor
@NoArgsConstructor(force=true, access= AccessLevel.PRIVATE)
public class User implements UserDetails {

 /*   @Id
    @Column(name = "username", length = 15)
    private String username;

    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "role")
    private String role;
*/

 @Id
 @GeneratedValue(strategy = GenerationType.IDENTITY)
 private Long id;
    private final String username;
    private final String password;
    private final String role;
    private boolean enabled;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.enabled;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.enabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.enabled;
    }
}