package master.nigaits.wapp.services;

import master.nigaits.wapp.entity.User;
import master.nigaits.wapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;

@Service
public class UserManagerService implements UserDetailsService {
    @Autowired
    UserRepository userManageRepository;


    public UserDetails loadUserByemail(String userid) throws UsernameNotFoundException {
        User user = userManageRepository.findByemail(userid);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid Username or password");
        }
        return new org.springframework.security.core.userdetails.User(user.getGid().toString(), user.getPassword(),
                mapRolesToAuthorities(user.getRoleId()));
    }

    public Collection<? extends GrantedAuthority> mapRolesToAuthorities(String desig_code) {
        return Collections.singletonList(new SimpleGrantedAuthority(desig_code));

    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userManageRepository.findByemail(username);
        return (UserDetails) user;

    }
}

