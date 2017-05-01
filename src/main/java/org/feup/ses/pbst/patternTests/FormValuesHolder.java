package org.feup.ses.pbst.patternTests;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import org.feup.ses.pbst.Utils.Utils;

public class FormValuesHolder {

    private String method = null;
    private String action = null;
    private String inputUsername = null;
    private String inputPassword = null;
    private String username = null;
    private String password = null;

    public FormValuesHolder(String protocol, int port, String host, String path, Map<String, List<String>> forms) {
        try {
            extractInputs(new URL(protocol, host, port, ""), path, forms);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    public FormValuesHolder(final URL url, final String path, final Map<String, List<String>> forms) {
        extractInputs(url, path, forms);
    }

    private void extractInputs(final URL url, final String path, final Map<String, List<String>> forms) {

        outer:
        for (String form : forms.keySet()) {
            method = Utils.extractParameterValue(form, "method");
            action = Utils.getCompleteLink(Utils.extractParameterValue(form, "action"), url.getProtocol(), url.getPort(), url.getHost(), path);

            if (method != null && action != null) {
                List<String> inputs = forms.get(form);
                for (String input : inputs) {
                    String type = Utils.extractParameterValue(input, "type");
                    if ("password".equals(type)) {
                        inputPassword = Utils.extractParameterValue(input, "name");
                    } else if (type != null && type.equals("text") || type.equals("number") || type.equals("email")) {
                        inputUsername = Utils.extractParameterValue(input, "name");
                    }
                    if (inputPassword != null && !"".equals(inputPassword) && inputUsername != null && !"".equals(inputUsername)) {
                        break outer;
                    }
                }
            }
        }
    }

    public String getMethod() {
        return method;
    }

    public String getAction() {
        return action;
    }

    public String getInputUsername() {
        return inputUsername;
    }

    public String getInputPassword() {
        return inputPassword;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((action == null) ? 0 : action.hashCode());
        result = prime * result + ((inputPassword == null) ? 0 : inputPassword.hashCode());
        result = prime * result + ((inputUsername == null) ? 0 : inputUsername.hashCode());
        result = prime * result + ((method == null) ? 0 : method.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        FormValuesHolder other = (FormValuesHolder) obj;
        if (action == null) {
            if (other.action != null) {
                return false;
            }
        } else if (!action.equals(other.action)) {
            return false;
        }
        if (inputPassword == null) {
            if (other.inputPassword != null) {
                return false;
            }
        } else if (!inputPassword.equals(other.inputPassword)) {
            return false;
        }
        if (inputUsername == null) {
            if (other.inputUsername != null) {
                return false;
            }
        } else if (!inputUsername.equals(other.inputUsername)) {
            return false;
        }
        if (method == null) {
            if (other.method != null) {
                return false;
            }
        } else if (!method.equals(other.method)) {
            return false;
        }
        return true;
    }
}
