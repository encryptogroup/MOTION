
public class test {

  public int f() { return 1; }

  public static void g(container c) {

    if(c == null)
      return;
    test[] args = c.test_array;
    if(args == null || args.length != 1 || args[0] == null)
      return;
    asserthere.doassert(args[0].f() == 1);

  }

}

class container {
  public test[] test_array;
}

class asserthere {

  // Used to avoid lazy-loading currently marking any class with an
  // $assertionsEnabled member (i.e. any class that asserts) as needed.
  public static void doassert(boolean condition) { assert(condition); }

}
