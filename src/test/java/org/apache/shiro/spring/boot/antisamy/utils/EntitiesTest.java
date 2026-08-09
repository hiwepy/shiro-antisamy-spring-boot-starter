package org.apache.shiro.spring.boot.antisamy.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Entities Tests")
class EntitiesTest {

    @Test
    @DisplayName("HTML40 entityName returns null for unknown char")
    void testEntityNameUnknown() {
        assertThat(Entities.HTML40.entityName((char) 0)).isNull();
    }

    @Test
    @DisplayName("HTML40 entityName returns name for known char")
    void testEntityNameKnown() {
        // ampersand
        String name = Entities.HTML40.entityName('&');
        assertThat(name).isNotNull();
    }

    @Test
    @DisplayName("HTML40 entityValue returns -1 for unknown name")
    void testEntityValueUnknown() {
        assertThat(Entities.HTML40.entityValue("unknown")).isEqualTo(-1);
    }

    @Test
    @DisplayName("HTML40 entityValue returns value for known name")
    void testEntityValueKnown() {
        int value = Entities.HTML40.entityValue("amp");
        assertThat(value).isEqualTo('&');
    }
}
