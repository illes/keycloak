/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.common;

import java.io.File;
import java.io.FileInputStream;
import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class Profile {

    public enum Feature {
        ACCOUNT2,
        AUTHORIZATION,
        DOCKER,
        IMPERSONATION,
        OPENSHIFT_INTEGRATION,
        SCRIPTS,
        TOKEN_EXCHANGE
    }

    private enum ProductValue {
        KEYCLOAK(),
        RHSSO(Feature.ACCOUNT2);

        private List<Feature> excluded;

        ProductValue(Feature... excluded) {
            this.excluded = Arrays.asList(excluded);
        }
    }

    private enum ProfileValue {
        PRODUCT(Feature.AUTHORIZATION, Feature.SCRIPTS, Feature.DOCKER, Feature.ACCOUNT2, Feature.TOKEN_EXCHANGE),
        PREVIEW(Feature.ACCOUNT2),
        COMMUNITY(Feature.DOCKER, Feature.ACCOUNT2);

        private List<Feature> disabled;

        ProfileValue(Feature... disabled) {
            this.disabled = Arrays.asList(disabled);
        }
    }

    private static final Profile CURRENT = new Profile();

    private final ProductValue product;

    private final ProfileValue profile;

    private final Set<Feature> disabledFeatures = new HashSet<>();

    private Profile() {
        product = "rh-sso".equals(Version.NAME) ? ProductValue.RHSSO : ProductValue.KEYCLOAK;

        try {
            Properties props = new Properties();

            String jbossServerConfigDir = System.getProperty("jboss.server.config.dir");
            if (jbossServerConfigDir != null) {
                File file = new File(jbossServerConfigDir, "profile.properties");
                if (file.isFile()) {
                    props.load(new FileInputStream(file));
                }
            }

            if (System.getProperties().containsKey("keycloak.profile")) {
                props.setProperty("profile", System.getProperty("keycloak.profile"));
            }

            for (String k : System.getProperties().stringPropertyNames()) {
                if (k.startsWith("keycloak.profile.feature.")) {
                    props.put(k.replace("keycloak.profile.feature.", "feature."), System.getProperty(k));
                }
            }

            if (props.containsKey("profile")) {
                profile = ProfileValue.valueOf(props.getProperty("profile").toUpperCase());
            } else {
                profile = ProfileValue.valueOf(Version.DEFAULT_PROFILE.toUpperCase());
            }

            disabledFeatures.addAll(profile.disabled);
            disabledFeatures.removeAll(product.excluded);

            for (String k : props.stringPropertyNames()) {
                if (k.startsWith("feature.")) {
                    Feature f = Feature.valueOf(k.replace("feature.", "").toUpperCase());
                    if (props.get(k).equals("enabled")) {
                        disabledFeatures.remove(f);
                    } else if (props.get(k).equals("disabled")) {
                        disabledFeatures.add(f);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getName() {
        return CURRENT.profile.name().toLowerCase();
    }

    public static Set<Feature> getDisabledFeatures() {
        return CURRENT.disabledFeatures;
    }

    public static boolean isFeatureEnabled(Feature feature) {
        if (CURRENT.product.excluded.contains(feature)) {
            return false;
        }
        return !CURRENT.disabledFeatures.contains(feature);
    }

}
