* [setup logger](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L33)
* [load ca from config file](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L45)
* [load cert state](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L52)
* [load firewall](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L59)
* [get tunnel cidr](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L66)
* [parse safe routes](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L67)
* [parse unsafe routes](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L71)
* [start sshd server](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L76)
* [setup tunnel](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L134)
* [setup udp listener](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L168)
* [setup host maps](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L186-L203)
* [setup punchy](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L236)
* [setup lighthouse](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/main.go#L242-L316)


to start the actual network:

* [read packets from udp](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/interface.go#L177)
* [read packets rfom tunnel device](https://github.com/slackhq/nebula/blob/c726d20578c54deb98fa438ae6ce324ab719b259/interface.go#L182)