package org.umd.spore.cloud.utility;

/**
 * Created by lex on 8/10/15.
 */

import lombok.Getter;

@Getter
public enum LoadTypes {

    DEFAULT("load"), SIMPLESIGNATURE("loadSS"), CHAIN("loadChain");
    private String loadType;

    private LoadTypes(String lType) {
        loadType = lType;
    }

    public String getCliArg() {
        return String.format("-%s", this.getLoadType());
    }
}
