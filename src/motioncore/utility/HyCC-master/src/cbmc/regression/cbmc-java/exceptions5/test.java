class A extends Throwable {}
class B extends A {}
class C extends B {}
class D extends C {}public class test {
  public static void main (String arg[]) {
    try {
      D d = new D();
      C c = new C();
      B b = new B();
      A a = new A();
      A e = a;
      throw e;
    }
    catch(D exc) {
      System.out.println("D");
      assert false;
    }
    catch(C exc) {
      System.out.println("C");
      assert false;
    }
    catch(B exc) {
      System.out.println("B");
      assert false;
    }
    catch(A exc) {
      System.out.println("A");
    }
  }
}
