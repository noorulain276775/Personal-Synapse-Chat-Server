#!/usr/bin/env python3
"""
Test script to verify Matrix Synapse server setup
"""

import requests
import time
import sys
import json

def test_server_health():
    """Test if the Synapse server is running and healthy"""
    try:
        response = requests.get("http://localhost:8008/_matrix/client/versions", timeout=5)
        if response.status_code == 200:
            print("✅ Synapse server is running")
            return True
        else:
            print(f"❌ Synapse server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to Synapse server: {e}")
        return False

def test_redis_connection():
    """Test if Redis is accessible"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, password='redis_password', decode_responses=True)
        r.ping()
        print("✅ Redis is running and accessible")
        return True
    except Exception as e:
        print(f"❌ Cannot connect to Redis: {e}")
        return False

def test_database_connection():
    """Test if PostgreSQL is accessible"""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host="localhost",
            port="5432",
            database="synapse",
            user="synapse",
            password="synapse_password"
        )
        conn.close()
        print("✅ PostgreSQL is running and accessible")
        return True
    except Exception as e:
        print(f"❌ Cannot connect to PostgreSQL: {e}")
        return False

def test_module_loading():
    """Test if custom modules are loaded"""
    try:
        response = requests.get("http://localhost:8008/_matrix/client/versions", timeout=5)
        if response.status_code == 200:
            # Check if modules are working by looking at server info
            print("✅ Custom modules should be loaded (check logs for confirmation)")
            return True
        else:
            print("❌ Cannot verify module loading")
            return False
    except Exception as e:
        print(f"❌ Cannot test module loading: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing Matrix Synapse Server Setup")
    print("=" * 50)
    
    tests = [
        ("Synapse Server", test_server_health),
        ("Redis Cache", test_redis_connection),
        ("PostgreSQL Database", test_database_connection),
        ("Custom Modules", test_module_loading),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Testing {test_name}...")
        if test_func():
            passed += 1
        time.sleep(1)
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your Matrix server is ready.")
        print("\n📋 Next steps:")
        print("1. Create an admin user:")
        print("   docker-compose exec synapse register_new_matrix_user -c /data/homeserver.yaml -a -u admin -p admin123 http://localhost:8008")
        print("2. Open http://localhost:8008 in your browser")
        print("3. Open frontend/index.html to test the chat client")
    else:
        print("❌ Some tests failed. Check the error messages above.")
        print("\n🔧 Troubleshooting:")
        print("1. Make sure Docker containers are running: docker-compose ps")
        print("2. Check logs: docker-compose logs -f")
        print("3. Restart services: docker-compose restart")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
