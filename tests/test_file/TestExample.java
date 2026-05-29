import java.util.List;
import java.util.ArrayList;
import java.util.HashMap; // 未使用的import
import java.io.*; // 未使用的import
import static java.util.Collections.emptyList;

public class testExample { // 类名不规范
    private int BadlyNamedField; // 字段名不规范
    private static final int MAGIC_NUMBER = 42;
    
    public void BadlyNamedMethod() { // 方法名不规范
        System.out.println("Hello"); // 不应该使用System.out
        List<String> list = new ArrayList<>();
        
        // 魔法数字
        int result = 100 * 2; // 魔法数字100
        
        // 高复杂度方法
        if (true) {
            if (true) {
                if (true) {
                    if (true) {
                        if (true) {
                            System.out.println("Too complex");
                        }
                    }
                }
            }
        }
        
        // 空的catch块
        try {
            int test = 10 / 0;
        } catch (Exception e) {
            // 空的catch块
        }
    }
    
    public void emptyMethod() { // 空方法
        // 这个方法没有实现
    }
    
    public void anotherEmptyMethod() {
        // 另一个空方法
    }
    
    // 长行测试
    public void veryLongMethodNameThatExceedsTheRecommendedLineLengthAndShouldBeReportedByTheCodeInspector() {
        System.out.println("This is a very long line that should be reported because it exceeds the maximum allowed line length of 120 characters by quite a bit");
    }
}