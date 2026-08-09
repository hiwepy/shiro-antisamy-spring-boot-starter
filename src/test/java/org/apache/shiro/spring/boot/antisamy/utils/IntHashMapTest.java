package org.apache.shiro.spring.boot.antisamy.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("IntHashMap Tests")
class IntHashMapTest {

    @Test
    @DisplayName("put and get work correctly")
    void testPutGet() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.get(1)).isEqualTo("one");
    }

    @Test
    @DisplayName("get returns null for missing key")
    void testGetMissing() {
        IntHashMap map = new IntHashMap();
        assertThat(map.get(999)).isNull();
    }

    @Test
    @DisplayName("size returns correct count")
    void testSize() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        map.put(2, "two");
        assertThat(map.size()).isEqualTo(2);
    }

    @Test
    @DisplayName("isEmpty returns true for empty map")
    void testIsEmpty() {
        IntHashMap map = new IntHashMap();
        assertThat(map.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("isEmpty returns false for non-empty map")
    void testIsNotEmpty() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.isEmpty()).isFalse();
    }

    @Test
    @DisplayName("containsKey works correctly")
    void testContainsKey() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.containsKey(1)).isTrue();
        assertThat(map.containsKey(2)).isFalse();
    }

    @Test
    @DisplayName("containsValue works correctly")
    void testContainsValue() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.containsValue("one")).isTrue();
        assertThat(map.containsValue("two")).isFalse();
    }

    @Test
    @DisplayName("contains works correctly")
    void testContains() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.contains("one")).isTrue();
        assertThat(map.contains("two")).isFalse();
    }

    @Test
    @DisplayName("contains throws NPE for null value")
    void testContainsNull() {
        IntHashMap map = new IntHashMap();
        assertThatThrownBy(() -> map.contains(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("remove works correctly")
    void testRemove() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        Object removed = map.remove(1);
        assertThat(removed).isEqualTo("one");
        assertThat(map.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("remove returns null for missing key")
    void testRemoveMissing() {
        IntHashMap map = new IntHashMap();
        assertThat(map.remove(999)).isNull();
    }

    @Test
    @DisplayName("clear works correctly")
    void testClear() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        map.put(2, "two");
        map.clear();
        assertThat(map.isEmpty()).isTrue();
    }

    @Test
    @DisplayName("put overwrites existing value")
    void testPutOverwrite() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        Object old = map.put(1, "uno");
        assertThat(old).isEqualTo("one");
        assertThat(map.get(1)).isEqualTo("uno");
    }

    @Test
    @DisplayName("constructor with initial capacity")
    void testConstructorCapacity() {
        IntHashMap map = new IntHashMap(100);
        map.put(1, "one");
        assertThat(map.get(1)).isEqualTo("one");
    }

    @Test
    @DisplayName("constructor with capacity and load factor")
    void testConstructorCapacityLoadFactor() {
        IntHashMap map = new IntHashMap(10, 0.5f);
        map.put(1, "one");
        assertThat(map.get(1)).isEqualTo("one");
    }

    @Test
    @DisplayName("constructor throws for negative capacity")
    void testConstructorNegativeCapacity() {
        assertThatThrownBy(() -> new IntHashMap(-1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("constructor throws for zero load factor")
    void testConstructorZeroLoadFactor() {
        assertThatThrownBy(() -> new IntHashMap(10, 0.0f)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("handles hash collision with rehash")
    void testHashCollision() {
        IntHashMap map = new IntHashMap(2, 0.5f);
        for (int i = 0; i < 50; i++) {
            map.put(i, "value" + i);
        }
        assertThat(map.size()).isEqualTo(50);
        for (int i = 0; i < 50; i++) {
            assertThat(map.get(i)).isEqualTo("value" + i);
        }
    }

    @Test
    @DisplayName("remove from chain")
    void testRemoveFromChain() {
        IntHashMap map = new IntHashMap(2, 0.75f);
        // Force collisions by using small capacity
        map.put(0, "zero");
        map.put(2, "two");
        map.put(4, "four");
        map.remove(2);
        assertThat(map.get(0)).isEqualTo("zero");
        assertThat(map.get(2)).isNull();
        assertThat(map.get(4)).isEqualTo("four");
    }

    @Test
    @DisplayName("toString returns non-null")
    void testToString() {
        IntHashMap map = new IntHashMap();
        map.put(1, "one");
        assertThat(map.toString()).isNotNull();
    }
}
