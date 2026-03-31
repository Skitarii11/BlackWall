import geoip2.database
import ipaddress

class GeoIPManager:
    def __init__(self, db_path='data/GeoLite2-City.mmdb'):
        try:
            self.reader = geoip2.database.Reader(db_path)
            print("GeoIP database loaded successfully.")
        except FileNotFoundError:
            self.reader = None
            print(f"Error: GeoIP database not found at {db_path}. Map feature will be disabled.")

    def get_location(self, ip):
        
        if self.reader is None:
            return None

        try:
            response = self.reader.city(ip)
            location = (
                response.location.latitude,
                response.location.longitude,
                response.city.name,
                response.country.name
            )
            return location
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None