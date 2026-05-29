import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

/**
 * 良好的代码示例
 */
public class GoodExample {
    private static final Logger LOGGER = Logger.getLogger(GoodExample.class.getName());
    private static final int MAX_RETRY_COUNT = 3;
    private static final double PI_VALUE = 3.14159;
    
    private String properlyNamedField;
    private int anotherField;
    
    /**
     * 构造方法
     */
    public GoodExample() {
        this.properlyNamedField = "default";
        this.anotherField = 0;
    }
    
    /**
     * 良好的方法示例
     * @param input 输入参数
     * @return 处理结果
     */
    public String properlyNamedMethod(String input) {
        if (input == null || input.isEmpty()) {
            LOGGER.warning("输入参数为空");
            return "default";
        }
        
        String result = processInput(input);
        LOGGER.info("处理结果: " + result);
        
        return result;
    }
    
    /**
     * 处理输入
     * @param input 输入
     * @return 结果
     */
    private String processInput(String input) {
        try {
            // 有意义的处理逻辑
            return input.toUpperCase();
        } catch (Exception e) {
            LOGGER.severe("处理输入时发生错误: " + e.getMessage());
            return "error";
        }
    }
    
    /**
     * 计算面积
     * @param radius 半径
     * @return 面积
     */
    public double calculateArea(double radius) {
        return PI_VALUE * radius * radius;
    }
}