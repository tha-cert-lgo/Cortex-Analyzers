#!/usr/bin/env python3
# Author: THA-CERT //LGO
from cortexutils.responder import Responder
import json
import ovh
from time import sleep

class OvhDomainOrder(Responder):
    def __init__(self):
        Responder.__init__(self)

        # API init
        self.api_ak = self.get_param("config.API_ak", None, "API Application key is missing")
        self.api_as = self.get_param("config.API_as", None, "API Application secret is missing")
        self.api_cs = self.get_param("config.API_cs", None, "API Consumer secret is missing")

        self.api_url = "https://api.ovh.com"

        # Vars init
        try:
            split_domain =  self.get_data().get("data", None).split(".")
        except:
            exit("Invalid data (not a string)")

        if len(split_domain) > 2:
            self.domain = split_domain[-2] + "." + split_domain[-1]
        elif len(split_domain) == 2:
            self.domain = self.get_data().get("data", None)
        else:
            exit("Invalid data (domain without dot)")

        self.price_limit = self.get_param("config.price_limit", None)
        if self.price_limit is None:
            self.price_limit = 20

        self.tags_to_buy = self.get_param("config.tags_to_buy", None)
        if self.tags_to_buy == [None]:
            self.tags_to_buy = None

        self.required_configuration = dict()
        if self.get_param("config.required_configuration", [None]) is not None:
            for conf in self.get_param("config.required_configuration", None):
                if conf is None: continue
                s_conf = conf.split(':')
                # Convert boolean values from str to bool
                if s_conf[-1] in ["True", "true"]: # -1 index to limite possible errors
                    s_conf[-1] = True
                elif s_conf[-1] in ["False", "false"]:
                    s_conf[-1] = False
                # Set value
                self.required_configuration[s_conf[0]] = s_conf[-1] # -1 index to limite possible errors

        self.domain_redirection = self.get_param("config.domain_redirection", None)
        if self.domain_redirection == "":
            self.domain_redirection = None


    def run(self):
        Responder.run(self)

        # Prepare report variable
        data = {}

        # Check on data type
        if self.get_data().get("dataType", None) != "domain":
            self.report({"errors": {"status": "Not_a_DN", "message": "Observable is not a domain name. This Responder runs only on Observable of type 'domain'."}})
            return

        # Create a session
        self.create_client()
        # Create a cart
        cart_id = self.create_cart()
        available_domains = self.get_available_offers(cart_id)
        # Check domain availability ('create'/'transfer') and type ('standard'/'premium')
        if len(available_domains) != 1:
            message = "While checking available domains, OVH returned %d domains name".format(len(available_domains))
            self.report({"errors": {"status": "multi_DN_returned", "message": message}})
            return

        # Check if domain is available ('create')
        action = available_domains[0].get("action", False)
        if action != "create":
            self.report({"errors": {"status": "DN_not_available", "message": f"{self.domain} doesn't seem to be available, action is '{action}'"}})
            return
        # Check if domain type is 'standard' (not 'premium')
        pricing_mode = available_domains[0].get("pricingMode", False)
        if pricing_mode != "default":
            self.report({"errors": {"status": "DN_is_premium", "message": f"{self.domain} has a particular status, princing mode is '{pricing_mode}'"}})
            return

        # Add domain in cart
        item_id = self.add_item_in_chart(cart_id).get("itemId", None)

        # Assign cart
        try:
            self.assign_cart(cart_id)
        except:
            pass # Return error if already assigned. As it's assigned, can continue.
        
        # Check if required configuration is needed
        required_conf = self.get_item_required_conf(cart_id, item_id)
        for conf in required_conf:
            if conf.get("label", "NO_LABEL") in self.required_configuration.keys():
                # Add required confirguration
                r = self.add_item_required_conf(
                    cart_id,
                    item_id,
                    conf.get("label"),
                    self.required_configuration[conf.get("label")]
                )
            elif conf.get('required', True): # Detect when required configuration is not set in parameters.
                message = "One required configuration is missing: %s doesn't seem to be set.".format(str(conf.get("label", "'label' keyword is missing")))
                self.report({"errors": {"status": "miss_config", "message": message}})
                return

        # Cart checking before validating
        bill_check = self.cart_validation_check(cart_id)
        # Init vars to check price limit
        price_whit_tax = bill_check.get("prices", {}).get("withTax", {}).get("value", None)
        if price_whit_tax is None: # Exit in case of error
            self.report({"errors": {"status": "no_price_value", "message": "Error while checking price limit. Not value from OVH response."}})
            return
        # Save price in results
        data["prices"] = {"without_tax": price_whit_tax}
        # Check price limit
        if self.price_limit is not None :
            data["prices"]["limit"] = self.price_limit
            if price_whit_tax > self.price_limit:
                message = f"{self.domain} is too expensive to be bought ({price_whit_tax} euros, limit is set at {self.price_limit} euros)"
                self.report({"errors": {"status": "too_expensive", "message": message}})
                return
            else:
                data["results"] = {}
                data["results"]["status"] = "can_be_bought"
                data["results"]["message"] = f"{self.domain} can be bought ({price_whit_tax} euros, limit is set at {self.price_limit} euros)"

        # # Validate cart (payment)
        # bill = self.cart_validation(cart_id)

        # # Domain redirection (if set)
        # if self.domain_redirection is not None:
        #     # Wait for 5 seconds to ensure that domain acquirement is well-done.
        #     sleep(5)
        #     # Set redirection on DN and "www" sub-domain
        #     r_empty = self.set_domain_redirection(self)
        #     r_www = self.set_domain_redirection(self, "www")
        #     # Refresh DNS zone to apply changes
        #     self.apply_domain_redirection()

        self.report(data)


    # def artifacts(self, raw):
    #     artifacts = []
    #     artifacts.append(self.build_artifact('data_type', 'data', tags = []))

    #     return artifacts


    def operations(self, raw):
        operations = []

        # Check potential errors
        if raw.get("errors", False):
            operations.append(self.build_operation('AddTagToArtifact', tag = "ovh:error:" + raw["errors"].get("status", "no_status")))
            operations.append(self.build_operation('AddTagToArtifact', tag = "ovh:error:" + raw["errors"].get("message", "no_message")))
            return operations

        if raw.get("results", False):
            operations.append(self.build_operation('AddTagToArtifact', tag = "ovh:domain:" + raw["results"].get("status", "no_status")))
            operations.append(self.build_operation('AddTagToArtifact', tag = "ovh:domain:" + raw["results"].get("message", "no_message")))

        return operations


    # Generic functions, trying to match API documentation
    def create_client(self):
        self.client = ovh.Client(
            endpoint = 'ovh-eu',
            application_key = self.api_ak,
            application_secret = self.api_as,
            consumer_key = self.api_cs,
        )

    def create_cart(self):
        retry = 3
        while retry > 0:
            try:
                r = self.client.post('/order/cart',
                    description = "Buying domain" + self.domain,
                    # "expire":null,
                    ovhSubsidiary = "FR"
                )
                return r.get("cartId", None)

            except:
                sleep(2)
                retry -= 1

        exit("Error while creating cart")


    # # TMP
    # def get_contacts(self):
    #     r = self.client.get('/me/contact/21440499')
    #     return r
    # # TMP
    # def get_domain_redirections(self):
    #     r = self.client.get('/domain/zone/thalessmartdefence.com/redirection')
    #     # 5266266666, 5266266667
    #     return r
    # # TMP
    # def get_domain_redirection(self):
    #     r = self.client.get('/domain/zone/thalessmartdefence.com/redirection/5266266667') # 5266266666, 5266266667
    #     return r


    def get_available_offers(self, cart_id):
        retry = 3
        while retry > 0:
            try:
                r = self.client.get(f'/order/cart/{cart_id}/domain',
                    domain = self.domain
                )
                return r

            except:
                sleep(2)
                retry -= 1

        exit("Error while getting available offers")



    def add_item_in_chart(self, cart_id):
        retry = 3
        while retry > 0:
            try:
                r = self.client.post(f'/order/cart/{cart_id}/domain',
                    domain = self.domain,
                    duration = "P1Y",
                    # pricingMode = 
                )
                return r

            except:
                sleep(2)
                retry -= 1

        exit("Error while adding item to cart")


    def assign_cart(self, cart_id):
        r = self.client.post(f'/order/cart/{cart_id}/assign')
        return r


    def get_item_required_conf(self, cart_id, item_id):
        retry = 3
        while retry > 0:
            try:
                r = self.client.get(f'/order/cart/{cart_id}/item/{item_id}/requiredConfiguration')
                return r

            except:
                sleep(2)
                retry -= 1

        exit("Error while requesting required conf")


    def add_item_required_conf(self, cart_id, item_id, label, value):
        retry = 3
        while retry > 0:
            try:
                r = self.client.post(f'/order/cart/{cart_id}/item/{item_id}/configuration',
                    label = label,
                    value = value
                )
                return r

            except:
                sleep(2)
                retry -= 1

        exit("Error while adding item conf")


    def cart_validation_check(self, cart_id):
        retry = 3
        while retry > 0:
            try:
                r = self.client.get(f'/order/cart/{cart_id}/checkout')
                return r

            except:
                sleep(2)
                retry -= 1

        exit("Error while checking cart")


    # def cart_validation(self, cart_id):
    #     retry = 3
    #     while retry > 0:
    #         try:
    #             r = self.client.post(f'/order/cart/{cart_id}/checkout')
    #             return r

    #         except:
    #             sleep(2)
    #             retry -= 1

    #     exit("Error while validating cart")


    def set_domain_redirection(self, sub_domain = None):
        retry = 3
        while retry > 0:
            try:
                r = self.client.post(f'/domain/zone/{self.domain}/redirection', 
                    subDomain = sub_domain, # subdomain to redirect (type: string)
                    target = self.domain_redirection, # Target of the redirection (type: string)
                    type = "visiblePermanent", # Redirection type (type: zone.RedirectionTypeEnum)
                )
                return r

            except:
                sleep(2)
                retry -= 1

        exit(f"Error while setting new redirection for DN {self.domain}")


    def apply_domain_redirection(self):
        retry = 3
        while retry > 0:
            try:
                r = self.client.post(f'/domain/zone/{self.domain}/refresh')
                return r

            except:
                sleep(2)
                retry -= 1

        exit(f"Error while refreshing {self.domain} DNS zone")


if __name__ == "__main__":
    OvhDomainOrder().run()