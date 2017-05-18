package org.feup.ses.pbst.Enums;

/**
 * Created by mzamith on 18/05/2017.
 */
public enum AuthHeader {

    COOKIE ("Cookie"),
    AUTHORIZATION ("Authorization");

    private String header;

    AuthHeader(String header){
        this.header = header;
    }

    public String header(){
        return this.header;
    }

}
