public class Test {

  public int foo(int x, int y) {
    if (x > 10) {
      return x;
    } else {
      return y * 10;
    }
  }

  public int bar(int x) {
    if (x < 10) {
      return x;
    } else {
      return x / 10;
    }
  }
}
