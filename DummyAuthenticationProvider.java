package org.example;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.databind.JsonNode;

public class DummyAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static final Logger LOG = Logger.getLogger(DummyAuthenticationProvider.class.getCanonicalName());

    private static final String DEFAULT_ROLE_NAME = "everyone";
    private static final String ROLE_PREFIX = "ROLE_";


    private final String username, password;
    private final boolean anyUser;

    private List<String> userGroups;

    public DummyAuthenticationProvider(String username, String password, boolean anyUser) {
        super();
        this.username = username;
        this.password = password;
        this.anyUser = anyUser;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        LOG.info(String.format("additionalAuthenticationChecks requested on %s details with %s authentication", userDetails, authentication));
    }

    @Override
    protected UserDetails retrieveUser(String username,
                                       UsernamePasswordAuthenticationToken authentication) {

        Object creds = authentication.getCredentials();
        if (creds != null && String.class.isAssignableFrom(creds.getClass())) {
            String pw = (String) creds;
            boolean valid = false;
            if ((this.anyUser && this.password.equals(pw)) ||
                    (!this.anyUser && this.username.equalsIgnoreCase(username) && this.password.equals(pw))) {
                valid = true;
            }

            if (valid) {
            	List<GrantedAuthority> authorities = getGrantedAuthorities(getUserGroups());
                MyUser user;
                switch (username) {
                case "john":
                	user = new MyUser("1111-1111-1-111111111111", "John", pw, authorities);
                	break;
                case "peter":
                	user = new MyUser("2222-2222-2-333333333333", "Peter", pw, authorities);
                	break;
                case "alice":
                	user = new MyUser("3333-3333-3-333333333333", "Alice", pw, authorities);
                	break;
                case "mary":
                default:
                	user = new MyUser("4444-4444-4-444444444444", "Mary", pw, authorities);
                }
                RestClientSource<TestAuthenticatedRestClient> clientSource = new RestUtils.RestClientSourceImpl<>("testAuthenticatedClient");
                try (RestClientSource.RestClient<TestAuthenticatedRestClient> client = clientSource.lease()) {
	                String userSerial = client.get().getCustomerSerial(user.getPid());
	            	if (userSerial != null) {
	            		user.setSerial(userSerial);
	            		JsonNode customer = client.get().getCustomer(CustomerIdType.serial, userSerial);
	            		if (customer != null) {
	            			String ctr = customer.get("ctr").asText();
	            			user.setCtr(ctr);
	            		}
	            	}
                } catch (IOException e) {
                	LOG.warning("IOException in communication with backed");
                }
                return user;
            }
            throw new BadCredentialsException("Invalid credentials!!");
        }

        // creds should never be null, so we shouldn't ever end up here
        throw new IllegalStateException("Unreachable code");
    }

    private List<String> getUserGroups() {
        return userGroups!= null ? userGroups : new ArrayList<>();
    }

    public void setUserGroups(final List<String> userGroups) {
        this.userGroups = userGroups;
    }

    /**
     * Returns the granted user groups based on the spring configuration
     */
    static List<GrantedAuthority> getGrantedAuthorities(List<String> userGroups) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        //set the user groups based on the spring configuration
        boolean defaultRoleAdded = false;
        for (String groupName : userGroups) {
            String prefixedRoleName = ROLE_PREFIX + groupName;
            authorities.add(new SimpleGrantedAuthority(prefixedRoleName));
            defaultRoleAdded = true;
        }

        //if no group is added than the everyone group will still be added
        if (!defaultRoleAdded) {
            String prefixedRoleName = ROLE_PREFIX + DEFAULT_ROLE_NAME;
            authorities.add(new SimpleGrantedAuthority(prefixedRoleName));
        }
        return authorities;
    }

    class MyUser extends User {

        private static final long serialVersionUID = 1L;

        private final String fullName;
        private final AtomicReference<String> ctr = new AtomicReference<>();
        private final AtomicReference<String> serial = new AtomicReference<>();

        /**
         * @param pid the myid pid/username
         * @param authorities the granted authorities
         */
        public MyUser(final String pid, final String fullName, final String myidToken, final Collection<? extends GrantedAuthority> authorities) {
            super(pid, myidToken, authorities);
            this.fullName = Objects.requireNonNull(fullName);
        }

        public String getPid() {
            return getUsername();
        }

        public void setCtr(String cpr) {
            this.ctr.set(cpr);
        }

        public String getCtrFull() {
            return ctr.get();
        }

        public String getCtr() {
            return ctr.get();
        }

        public void setSerial(String serial) {
            this.serial.set(serial);
        }

        public String getSerial() {
            return serial.get();
        }

        public String getFullName() {
            return fullName;
        }

        @Override
        public String toString() {
            return "MyIdUser [" + fullName + " {" + getPid() + ", ctr=" + getCtr() + "}]";
        }
    }

}



