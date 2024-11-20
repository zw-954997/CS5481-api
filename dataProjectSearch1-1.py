import requests
import pandas as pd
from geopy.distance import geodesic
from fuzzywuzzy import process
import json

# 默认IP地址（当无法自动获取IP时使用）
DEFAULT_IP = "111.125.113"

# 加载医院数据
hospital_data = pd.read_csv('hospital_data.csv')  # 替换为你的文件路径
hospital_data.columns = hospital_data.columns.str.strip()

hospital_data['Lattitude'] = pd.to_numeric(hospital_data['Lattitude'], errors='coerce')
hospital_data['Longitude'] = pd.to_numeric(hospital_data['Longitude'], errors='coerce')

# 获取用户公网IP地址
def get_public_ip():
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        response.raise_for_status()
        print(response.json()["ip"])
        return response.json()["ip"]
    except Exception as e:
        print(f"Failed to get public IP, using default: {DEFAULT_IP} ({e})")
        return DEFAULT_IP

# 获取IP地址对应的经纬度
def get_coordinates_from_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            return data['lat'], data['lon']
        else:
            raise ValueError("can not explain information for ID address")
    except Exception as e:
        raise ValueError(f"fail to get the location: {e}")


def match_department(target_department, department_column):
    # 从整列生成唯一科室列表
    hospital_departments = department_column.str.split(', ').explode().unique()
    matched_department, score = process.extractOne(target_department, hospital_departments)
    return matched_department


# 查询最近的医院
def find_nearest_hospital(hospital_data, ip, target_department):
    # 获取用户经纬度
    user_coords = get_coordinates_from_ip(ip)
    
    # 提取医院经纬度坐标
    hospital_data['Coords'] = list(zip(hospital_data['Lattitude'], hospital_data['Longitude']))
    
    # 模糊匹配科室
    hospital_data['Matched_Department'] = match_department(target_department, hospital_data['Department'])
    
    # 计算每家医院与用户的距离
    hospital_data['Distance'] = hospital_data['Coords'].apply(
        lambda coords: geodesic(user_coords, coords).kilometers
    )
    
    # 找到距离最近的医院
    nearest_hospital = hospital_data.loc[hospital_data['Distance'].idxmin()]
    
    # 构造返回结果
    answer = {
        "Hospital Name": nearest_hospital['Hospital Name'],
        "Address": nearest_hospital['Address'],
        "Distance (km)": round(nearest_hospital['Distance'], 2),
        "Contact": nearest_hospital['Contact'],
        "Department": nearest_hospital['Matched_Department']
    }
    return answer


def main(target_department):
    try:
        # 默认IP地址（当无法自动获取IP时使用）
        DEFAULT_IP = "111.125.113"

        hospital_data = pd.read_csv('hospital_data.csv')  
        hospital_data.columns = hospital_data.columns.str.strip()
        
        hospital_data['Lattitude'] = pd.to_numeric(hospital_data['Lattitude'], errors='coerce')
        hospital_data['Longitude'] = pd.to_numeric(hospital_data['Longitude'], errors='coerce')

        
        ip_address = get_public_ip()

        result = find_nearest_hospital(hospital_data, ip_address, target_department)
        
        # 5. 输出结果
        result_json = json.dumps(result, ensure_ascii=False)
        return result_json
    except Exception as e:
        print(f"error: {e}")

# 调用主函数
if __name__ == "__main__":
    department = "Throat"  
    print(main(department))
