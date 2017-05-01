package org.feup.ses.pbst;

import java.io.Serializable;
import org.feup.ses.pbst.Enums.AccessLevel;

public class AccessCredential implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private AccessLevel accessLevel;

    public AccessCredential(String username, String password, AccessLevel accessLevel) {
        super();
        this.username = username;
        this.password = password;
        this.accessLevel = accessLevel;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public AccessLevel getAccessLevel() {
        return accessLevel;
    }

    public void setAccessLevel(AccessLevel accessLevel) {
        this.accessLevel = accessLevel;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || (getClass() != obj.getClass())) {
            return false;
        }

        AccessCredential other = (AccessCredential) obj;

        if (username == null) {
            if (other.username != null) {
                return false;
            }
        } else if (!username.equals(other.username)) {
            return false;
        }
        return true;
    }
}
