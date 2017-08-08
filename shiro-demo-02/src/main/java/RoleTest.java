import org.apache.shiro.authz.UnauthorizedException;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class RoleTest extends BaseTest{


    @Test
    public void testHasRole() {
        login("classpath:shiro-role.ini", "admin", "123");

        //判断拥有角色:role1
        Assert.assertTrue(subject().hasRole("role1"));
        //判断拥有角色:role1,role2
        Assert.assertTrue(subject().hasAllRoles(Arrays.asList("role1", "role2")));
        //判断拥有角色：role1 and role2 and !role3`
        boolean[] result = subject().hasRoles(Arrays.asList("role1", "role2", "role3"));
        System.out.println(result[0]);
        System.out.println(result[1]);
        System.out.println(result[2]);
        Assert.assertEquals(true, result[0]);
        Assert.assertEquals(true, result[1]);
        Assert.assertEquals(false, result[2]);
    }

    @Test
    public void testIsPermission() {
        login("classpath:shiro-permission.ini", "admin", "123");

        //判断拥有的权限:user:create
        Assert.assertTrue(subject().isPermitted("user:create"));

        //判断拥有权限:user:create and user:delete
        Assert.assertTrue(subject().isPermittedAll("user:create", "user:delete"));

        //判断没有权限
        Assert.assertFalse(subject().isPermitted("user:view"));
    }

    @Test(expected = UnauthorizedException.class)
    public void testCheckPermission() {
        login("classpath:shiro-permission.ini", "admin", "123");

        //断言拥有权限user:create
        subject().checkPermission("user:create");
        //断言拥有权限user:create,user:delete
        subject().checkPermissions("user:create", "user:delete");
        //断言拥有权限user:view 失败!抛出异常
        subject().checkPermissions("user:view");
    }
}
