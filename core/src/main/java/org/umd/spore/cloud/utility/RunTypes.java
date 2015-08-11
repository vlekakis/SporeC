package org.umd.spore.cloud.utility;

import lombok.Getter;

/**
 * Created by lex on 8/10/15.
 */
@Getter
public enum RunTypes {
    DEFAULT("run"), SIMPLESIGNATURE("runSS"), CHAIN("runChain");

    private String runType;
    private RunTypes(String rType) {
        runType = rType;
    }

    public String getCliArg() {
        return String.format("-%s", this.getRunType());
    }

}
