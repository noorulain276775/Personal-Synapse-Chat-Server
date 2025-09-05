#!/usr/bin/env python3
"""
Authentication System Test Script
Tests all authentication features and modules
"""

import asyncio
import aiohttp
import json
import time
import sys
from typing import Dict, Any

class AuthTester:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = None
        self.auth_token = None
        self.test_results = []
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message
        })
    
    async def test_health_check(self):
        """Test API health check"""
        try:
            async with self.session.get(f"{self.base_url}/api/health") as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test("Health Check", True, f"API is healthy - {data['users_count']} users")
                else:
                    self.log_test("Health Check", False, f"Status: {response.status}")
        except Exception as e:
            self.log_test("Health Check", False, f"Error: {e}")
    
    async def test_user_registration(self):
        """Test user registration"""
        try:
            test_user = {
                "username": "testuser",
                "email": "test@example.com",
                "display_name": "Test User",
                "password": "TestPassword123!"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/auth/register",
                json=test_user
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test("User Registration", True, f"User created: {data['user_id']}")
                else:
                    error_data = await response.json()
                    self.log_test("User Registration", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("User Registration", False, f"Error: {e}")
    
    async def test_user_login(self):
        """Test user login"""
        try:
            login_data = {
                "username": "testuser",
                "password": "TestPassword123!"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/auth/login",
                json=login_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data["access_token"]
                    self.log_test("User Login", True, f"Login successful: {data['user_id']}")
                else:
                    error_data = await response.json()
                    self.log_test("User Login", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("User Login", False, f"Error: {e}")
    
    async def test_get_profile(self):
        """Test getting user profile"""
        if not self.auth_token:
            self.log_test("Get Profile", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.get(
                f"{self.base_url}/api/user/profile",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test("Get Profile", True, f"Profile retrieved: {data['username']}")
                else:
                    error_data = await response.json()
                    self.log_test("Get Profile", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Get Profile", False, f"Error: {e}")
    
    async def test_update_profile(self):
        """Test updating user profile"""
        if not self.auth_token:
            self.log_test("Update Profile", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            update_data = {
                "display_name": "Updated Test User",
                "email": "updated@example.com"
            }
            
            async with self.session.put(
                f"{self.base_url}/api/user/profile",
                json=update_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    self.log_test("Update Profile", True, "Profile updated successfully")
                else:
                    error_data = await response.json()
                    self.log_test("Update Profile", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Update Profile", False, f"Error: {e}")
    
    async def test_change_password(self):
        """Test changing password"""
        if not self.auth_token:
            self.log_test("Change Password", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            password_data = {
                "old_password": "TestPassword123!",
                "new_password": "NewPassword123!"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/user/change-password",
                json=password_data,
                headers=headers
            ) as response:
                if response.status == 200:
                    self.log_test("Change Password", True, "Password changed successfully")
                else:
                    error_data = await response.json()
                    self.log_test("Change Password", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Change Password", False, f"Error: {e}")
    
    async def test_forgot_password(self):
        """Test forgot password functionality"""
        try:
            forgot_data = {"email": "test@example.com"}
            
            async with self.session.post(
                f"{self.base_url}/api/auth/forgot-password",
                json=forgot_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test("Forgot Password", True, f"Reset token generated: {data.get('reset_token', 'N/A')}")
                else:
                    error_data = await response.json()
                    self.log_test("Forgot Password", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Forgot Password", False, f"Error: {e}")
    
    async def test_admin_login(self):
        """Test admin login"""
        try:
            admin_data = {
                "username": "admin",
                "password": "admin123"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/auth/login",
                json=admin_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data["access_token"]
                    self.log_test("Admin Login", True, f"Admin login successful: {data['user']['role']}")
                else:
                    error_data = await response.json()
                    self.log_test("Admin Login", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Admin Login", False, f"Error: {e}")
    
    async def test_get_users_list(self):
        """Test getting users list (admin only)"""
        if not self.auth_token:
            self.log_test("Get Users List", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.get(
                f"{self.base_url}/api/admin/users",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    user_count = len(data["users"])
                    self.log_test("Get Users List", True, f"Retrieved {user_count} users")
                else:
                    error_data = await response.json()
                    self.log_test("Get Users List", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Get Users List", False, f"Error: {e}")
    
    async def test_password_validation(self):
        """Test password validation"""
        weak_passwords = [
            "123",
            "password",
            "Password",
            "Password1",
            "Password1!"
        ]
        
        for password in weak_passwords:
            try:
                test_user = {
                    "username": f"testuser_{int(time.time())}",
                    "email": f"test_{int(time.time())}@example.com",
                    "password": password
                }
                
                async with self.session.post(
                    f"{self.base_url}/api/auth/register",
                    json=test_user
                ) as response:
                    if response.status == 400:
                        error_data = await response.json()
                        if "Invalid password" in error_data.get("error", ""):
                            self.log_test(f"Password Validation ({password})", True, "Weak password rejected")
                        else:
                            self.log_test(f"Password Validation ({password})", False, f"Unexpected error: {error_data}")
                    else:
                        self.log_test(f"Password Validation ({password})", False, "Weak password accepted")
            except Exception as e:
                self.log_test(f"Password Validation ({password})", False, f"Error: {e}")
    
    async def test_username_validation(self):
        """Test username validation"""
        invalid_usernames = [
            "ab",  # Too short
            "a" * 21,  # Too long
            "123user",  # Starts with number
            "user-name",  # Contains hyphen
            "user.name",  # Contains dot
            "admin",  # Reserved word
        ]
        
        for username in invalid_usernames:
            try:
                test_user = {
                    "username": username,
                    "email": f"test_{int(time.time())}@example.com",
                    "password": "ValidPassword123!"
                }
                
                async with self.session.post(
                    f"{self.base_url}/api/auth/register",
                    json=test_user
                ) as response:
                    if response.status == 400:
                        error_data = await response.json()
                        if "Invalid username" in error_data.get("error", ""):
                            self.log_test(f"Username Validation ({username})", True, "Invalid username rejected")
                        else:
                            self.log_test(f"Username Validation ({username})", False, f"Unexpected error: {error_data}")
                    else:
                        self.log_test(f"Username Validation ({username})", False, "Invalid username accepted")
            except Exception as e:
                self.log_test(f"Username Validation ({username})", False, f"Error: {e}")
    
    async def test_logout(self):
        """Test user logout"""
        if not self.auth_token:
            self.log_test("Logout", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(
                f"{self.base_url}/api/auth/logout",
                headers=headers
            ) as response:
                if response.status == 200:
                    self.log_test("Logout", True, "Logout successful")
                    self.auth_token = None
                else:
                    error_data = await response.json()
                    self.log_test("Logout", False, f"Error: {error_data.get('error', 'Unknown error')}")
        except Exception as e:
            self.log_test("Logout", False, f"Error: {e}")
    
    async def run_all_tests(self):
        """Run all authentication tests"""
        print("🧪 Starting Authentication System Tests")
        print("=" * 50)
        
        # Basic functionality tests
        await self.test_health_check()
        await self.test_user_registration()
        await self.test_user_login()
        await self.test_get_profile()
        await self.test_update_profile()
        await self.test_change_password()
        await self.test_forgot_password()
        
        # Admin functionality tests
        await self.test_admin_login()
        await self.test_get_users_list()
        
        # Validation tests
        await self.test_password_validation()
        await self.test_username_validation()
        
        # Cleanup
        await self.test_logout()
        
        # Print summary
        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)
        
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("\n🎉 All tests passed! Authentication system is working correctly.")
        else:
            print(f"\n❌ {total - passed} tests failed. Please check the errors above.")
        
        return passed == total

async def main():
    """Main test function"""
    async with AuthTester() as tester:
        success = await tester.run_all_tests()
        return success

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
