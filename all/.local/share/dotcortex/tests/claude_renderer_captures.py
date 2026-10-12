"""Public captured bytes; decode before replaying the attributed screen model."""
import base64
import zlib


def captured(value):
    return zlib.decompress(base64.b64decode(value))


FULLSCREEN = {
    'native': {
        'empty': captured(
            'eJztVM1u00AQPnLqE/gy6gMk+2PHtowaEQNOuRRVjQBZVWU1TmPJm4TYBnHjhLiRAyoHGpU34MABzn0UPwmza7t12zSNEccmu7Ob'
            'ycx838zOrmZq/lyzNL/LjLGUhOjFyqlcqfp9SJz87Be4cZANQ3Cnw/CR+k+30Ya90Px+YUpKF1auvFw7KqQRV7K/pfmUuih6OEUt'
            'LobTPRRMaD63HOZQg1dTvGMt2mJ258p7b5YlYLQMuPgNT17uwiAJTkLoRXEcTU6uzNqpmLXf7A32j57vvj4Y7D87cl89hXUf9LWI'
            'K9n08m8LEOEwyoREaYej0XSebhXcC4q8U02Rf/34MDYcVQ1tkS9/XvzAYouD+QfYfj+P0hACSMMkBSw2PB5FcTgL0vHOdulT64+H'
            '4v9r8Zlbb+LaPcu//AERTLIgBoF3EqYT2flddRbJGLv/OEsTqco/LZQSL90kTdRRosBg+B5w4vB+9a7skLe4zbRD0yDU6eLrcXzt'
            'LUAWumRB5Lc6WkYNh1LbsUyRn37OT8+VJW7R2C5URQ/hfV2DXYNxG0G5q+FK9RLHZrCsESxbBysTNbwNs70f8hwtvEtkvhqZN054'
            'w2RlKpfg+h1pS2DJUmZuNsj8NuTiGqmKQser9VaJfSbVN61vNV3h26wqN1nBXbTMFbSWipl5H7PacUmKSM7y/nevflewkmSxU5H1'
            '1eH/Ap+rVyg='
        ),
        'busy': captured(
            'eJztVj9v2kAUHzvlE3g5ZewAvjM2tlwFFbc1aYZUUVBbWVGEwIAlzlD/adotylB1K0OVDgWl6tC1Q4d05qP4k/Sd7SMGDMGoY4zv'
            'zty9e7/fe/fu7glVwfIEVbBqRO6zWhQrSSth1uL4/5moR5M/yBi0wo6NjGHHfhSPVTSQIS8Fq5GIiukUkrZS2iqxSnnA68aeYGFs'
            'QFWHQjN6QV3FhIpQwZJUnehYlnih70kJl4im3M0+HoU+kksymt2ip68OUdNv9WxUdwYDx+3diZUDOiq/PW6enL84fHPaPHl+brx+'
            'hjY9MFcVDcamHn0bI2p3nJAylLLd7Q69YC/hnlCUFF5o9PXy4d3y5T7UaDT9PfsBzqan3ke0f+E5gY1aKLD9AIGz0ZOuM7BHraB/'
            'sJ/OycTHg/N3dT4xskGc2WfRl7+IttywNUAU9iQauizya/Fa+H2I/nYY+Kwr+jSOO2HTuYEfLyVUoAzOA0nUpQY/Vw7Ed/AZCmdV'
            'WcR6DU6P9sJZACwqjIXIfnxpCZZ1jDVdrdLo+nN0fRNLwicIa0lXEkOwXzdgZ2CMQlBGPlzaPYV3O1hSCJZsgmWGyuaW1t4PeQMS'
            '5hxZykeWChu8pbHMlDl4ZY3ZDJixZJZXC1i+CjleIMUpKGYmtlLsCetell4JumRuMa8ss0LraFVzaE1jZtX7mGWWi1EEcqr5v2P1'
            'ewzLSCZfseZKQfUZjSkGN+kq0X21o+INvFPSxRQTrd51PgShZyOoXDgPIU85Yr5W2SjAHmXVYI3rYXkTZA9LedNct8IJy3Ly5iU9'
            'cDcibgoIpYWuEgKLNqY0Oz3MA2Kde2rJn7Nb6DONPlCAdIuPSzAuazom4PDLXzkxz86U3GsnyQLilVnw7ooku3tsv42CIXLcwPa8'
            'cBQUuo8y66vkHRaTnwAvmjkm9XbX+liwtDyV7lqV/wCq8inY'
        ),
        'post-turn': captured(
            'eJztV8tu00AUXbLqF3gz6pJF6xk/EmPUihhwS4VaVa0KiqrKNE5jETvBDx67qgvErkVC7YJWRSzYskCiSIhNP8Vfwp2xnUySSRqn'
            'LEnssTOee8+5Z2aub6SKVA+lqlRfJlqLtrKsZlcF0ytmv3dlMz3/gay2kzRcZHUa7h32TDVgDHki1VeyoXJuQvKrkl915lJrF+3K'
            'nFTH2IKmBqfP+QV3qg0N8aW6UjWJiTWlOP3XZAEvEEPvW693kwhpCxq6vkIPNlbRduQcuKjmtdtecNAfthj73cXn69ube49Xn21t'
            'bz7as3YeokkfsK3KFmVTS89OkO82vMSnKItus9kJ47mMe0ZR0YvTTz8d/j+mPAoNDT+9+H79BcT2t8J3aP5N6MUuclDsRjECsdH9'
            'ptd2u07cWprPbbj18V/8WcUnFr+IuX2WHv9CvhMkThv5sCdRJ6Arf5nNRdSC1b+fxBHtSt+fsE7YdEEcsamEBpxBPlBkU1kp8sqS'
            '/ApuE2m3osnYXIbssT+QC4CFSlnI9FtMLcGaibFhVit+evohPb1kI+EWBhtZV7aGYL9OwOZgrFJQlhgu776AYzpYUgqWTIKlgWr2'
            'lNHeDHkJI+wesiJGVkoHPGWwNJQeuDombApMWdLIKyUiH4U8GSBVUNBtbm3l2Oe0e3j0yKLLbMupMswKjaNVEdC6YMwqNzHjpotS'
            'BHJV+1+v1c8MlpLM7phntaR7zmOOUYR0lPk+mtHxBN456XKOiVFrem/jJHQRNAHkQ6hT1qjWVfoUYNd4N9go/NC6CaqHobqp51sv'
            'CGtadoiKHng3oiIUGJSf/ighiGhiSTPThyog1wqlhvS8voI+22oBBSi3iucKPNcMExMQ/PCbYM3TnCJ87WRVAJuZAXVHRtJ3jxvt'
            'o7iDvCB2wzDpxqXeR9z86qJkcf4V4GVbENLB7F7vSnVD5DK4DdGftzH+TXODgJFHK2dbYMHmc2a4P1n2EgnAid23mE5rzRoA5PyG'
            'vOB9txP0Zhv249gNO15GTRRXwsvbN/BuOd+qCKvFazt1rKN/6nr41R48l3XSs2O65ZnT0HUaNMC4BckHE7ubvGh7UNZhw86T09yY'
            '7csUU+ydTvjSbbANi1k52YA8hjC5p6lo4ylNAHqNSwdKjSUI6hSPSwzT1qhrIkX+AoI5FLQ='
        ),
        'suggestion': captured(
            'eJztWEtv20YQPvbkX8DLIMcgsLl8SGJUxCjZlk6NwkFqIy2EIGAsSiLKh0Iu4+YW5FD01LhAkRxqI0EOvfZQoClQFAX8U/hLOrsk'
            'pZVE0pSctJfIfJncne+b2dlvh5S60iCWetJgV9En7CjLWn5WCTsT/v99uZ+d/Q6W76RDF6xo6H7En2kGtlG+kAZ7eVO56KIUZ7U4'
            'd7hJ3S+Pe1vSgBALDybugWAXzWk2HpRAGqi9vtInulruwWNlm2wrRmfe+2CaJqBv63DxFj65cxuOEmfsgun5vheO5812aDDd+ebg'
            '6O6Dz29/fXh097MH1r1PoemHfXuyxdiY2ctTCNyhlwYMZccdjaKYbuXcc4pqp9yD7OenH7aWWxlDI8jOf7t4jcEODuMncO0k9qgL'
            'DlA3oYDBho9Hnu9OHTq5da3oI+THh+BvGnzFEpNYmGfZ8z8hcMLU8SHAOQlRyDJ/l49FMsHsP05pwm5l35/ymzjpQprwocQDGkM9'
            'UOW+ulfqyi35EV6m0v2uLpP+LqrH8YIWIAuNsZDZXzm0CtH7hBj9XjfIXvyQvXjFW+IlNjbyW3kO4XxtwBZgrLWgrGq44vY5bu1g'
            'lbVglSZY5qhut/T2cshX2MKeIavVyOraDrd0lrkyA9dq3GbAjCXzvLuG56uQpwukSgodW8itAvuM3V5uvZJ0ed/1orLMCupodSto'
            'nXNm3cuYCcPFKCK5nv2uc/UXDstI5lfcsramecFigVG69Cy3/WxDww28C9LrGVYMc+R9R9PYBTyEqIdYp+yzWPfYU4TdF80Qo7TD'
            '6iasHpbqppntTklY1/OtqujBtRFKV7BRsQerhNCjxpJmox+LgGyWkVqK58VbvGdbE6SA5Vb5XMXnutEnCgb86a8VOc80pXLZyasA'
            'PjIL0V1pydYeNzkGGoEXUjeO0yldaz0SxrdTJRZnbxBetitcGm9u9bo0MKpMhlch+sdVOv/FtKGCkccqZ7uiBx/PjeH+ztWrKgBC'
            'sOc92sVatxYABbuxGPC52YZ48wn7U+2ErQ+jXuVXKoZ33sG74nhrVVgTMbatfV19qZvh92bwgupkL5+zKc+Nxq4zZA7SCYoPUexp'
            '+tD3sKwjhl2I01bN9OURU+17UfytO+QTlvBycog6BkS5qWtw50smAB1TkAPV5ALBjJI6YWhbo+5fGv0F2efTgSkt42TTk6it9ten'
            'ElHelfgjnfcn/jnNKvHn01m1D5IgSlD9URpg4aVYlGvIfvwHLl4fetOb8BV1YgonHp1AEji+DyPXYc4kgIP0MB0DOucmN/DtD58V'
            '0UOdn8bRNErYa+HUd8Ib4IRDeOzG3ugJeDjQhQ4QM0nHY3xvxLzCV3aazPPmP19YtDqt2LxzS7Gv6nz9KrhvNu/MagRhLVkpDpqE'
            'uL5yMqwFuHbr8yWCR7T3rnim0yx4PVHv2FTan+X1/6eB7LsM8xzQbchdhpku5h9iGs3k39G6y0pZNv0XHyCU0Q=='
        ),
        'typed': captured(
            'eJztWEtv20YQPvZk9AfwMsipCAKby4ckRkWMkm3oxAgcpDaSQggCxqIkonyVj7i5BTkEOTUuUCSH2kiQQ685FGgKFEUB/xT+ks4u'
            'SWklkTQlJ+0lMl8md+f7Znb22yGFrjCIhJ4w2JbUCT2KopKfZULPhP1/X+xnJ7+D4Vrp0AYjGNqfsWeKhm2km8JgJ28qFl2k4iwX'
            '5w4zqbrlcWdDGBBi4EHH3ePsojnFxIPkCQO515f6RJXL3XskbZJNSevMeu+FaQzqpgpn7+Gr2zfgILbGNuiO6zr+eNZsK/HCre/2'
            'Du48uH7j3v7BnW8eGHe/hqYf9u2JBmWjZ6+OwbOHTupRlC17NAqiZCPnnlOUO+XuZb88+bS13MoYal52+u7sDQbb248ew6WjyEls'
            'sCCx4wQw2PDlyHHt0Eom1y4Vfbj8+BT8dYMvGXwSc/Mse/EneJafWi54OCch8Gnmb7OxiCeY/YdpEtNb2bNjdhMnnZ/EbCjxgMZQ'
            'D2SxL++UunJN/AEvU+F+VxVJfxvV43BOC5CFQlmI9K8cWomofUK0fq/rZS+fZy9fs5Z4iY21/FaeQzhfG7A5GGMlKKMarrh9ils7'
            'WGklWKkJljqqmi29PR/yNbYwp8hyNbK8ssMtnaWuTMGVGrcpMGVJPe+u4Pky5PEcqZJCx+Ryq8A+obcXWy8lXd53tagssoI6Wt0K'
            'WqeMWfc8ZtxwUYpIrmd+6Fz9lcFSkvkVs6ysaJ6zWGCULj3NbT9d03AD74L0aoYlTR85PyZpZAMefNRDrFN2aax79CnC7vJmiFba'
            'oXUTVg8LddPUdqckrKr5VlX04NoIpSvYqNi9ZULoUWNJs9aPRkDUy0gtxPPsPd4zjQlSwHKrfC7jc1XrEwkD/uS3ipynmlK57ORV'
            'ABuZuegutaRrjx0fQhKA4yd2FKVhstJ6xI1vp0osTt4ivGhWuDRe3+plYaBVmfQvQvSPi3T+i2pDBSOHVs5mRQ82nmvD/Z2rV1UA'
            'uGDPerSLtWrMAXJ2Iz7gM7MN8WYT9ufaCVsfRrXKr5QP76yDc8HxVqqwJnxsW/u6/FI3xe9N4TnVyV69oFOeGY1sa0gdTCYoPkQy'
            'w/Sh62BZRzSzEKeNmunLIiabd4Poe3vIJixh5eQQdQyIdFVV4PYtKgAdnZMDWWcCQY2SOmFoW6Punhv9Odln04EqLeVkJkdBW+2v'
            'TyUifSjxRzofT/xzmlXiz6azbO7FXhCj+qM0wNxLMS/XkP30D5y92XfCq/BtYkUJHDnJBGLPcl0Y2RZ1JgYcpIfpGNA5O76Cb3/4'
            'rIge6nwYBWEQ09fC0LX8K2D5Q3hkR87oMTg40IUOED1Ox2N8b8S8wlf2JJ7lzX++sCh1WrF+55ZiX9X58kVw367fmdYI3FqyVBw0'
            'CXF95aQZc3Dt1udzBI8oH13xdKtZ8Hq83tGptDvN6/9PA+l3Geo5oNuQuwxTXcw/xDSayb+jdReVctr0C/1z7sNjq6+IHLsaZrUC'
            'LXUK3H8B6HyzoA=='
        ),
        'permission': captured(
            'eJztWktv20YQPvZk9AfosjB6KPJwRFLUIypiVEpKp0YaI7WRGkYQrKWVxYSvkMso7inIoeihaFIgTQ6NkSCHXnMo0BQoigL+Kfol'
            'nVk+tJJImZKSpgUsU5RE7s58M7vzzezSpVppzy/VS3vrqt7Hc7lciT41BT8V8ftWuTl88RtpWzTsMtJ2u+wjca/SgDbql6W9jahp'
            'Oe6ixp9a/FkVInUrOW+slPYUpQ2nFrxtSS6IqxhwUu3SnlZvqk1F15K3fV9dU9bURnXU+7oXBkRf08nxW/L51lWyE9ADRlqmZZnO'
            'wajZBW57F3av79y4/cXVb7Z3bly53b55mcx6Qd96uY1oWsPnT4jNumZoo5YLrNdzfb4SYY8gatXkbQ+fPjw9Ch6JDxv28OjN8Stw'
            'tr3tH5LVgW9yRijhLOAEnE0+65kW8yjvX1qN+0jz49T5izpfbcuTWIqz4eM/iE2dkFrEhpgkroMzf12MRdCH2d8JeYCXht89ERch'
            '6BweiKGEEwgDPtDKTW0j4ZVL5XvwNSzdqullpbkO7NEZ4wJAUUEUZfxLhlZV9KaiNJr1mj189v3w2UvREr5C40Z0KZpDEK8zdEtq'
            '2nOpameriy8fwVFMrTqXWnWWWjRUNwpae7LKl9DCSDVr2Zq1uQ0uaCyakiqv5JiNihElWl6bw/JplU/GQCUQqoY0t2LdL/DyZOup'
            'SRf1nc8rk6hIHqxaBqwjgax2EjJpuBAigKsb73qu/iLUIsjom5BcmVO8JDHWkZj0KJL9aEHBM3DHoOcTrDZaPfMBD31G4OQAH0Kd'
            'som+ruNdULspi1EaiRysm6B6mKibUtnVBLCuR0dW0QO5kSSmQKP4bU8DAotmljQLvdAD5VbiqQl/Hr+Fa0a7DxCg3Erua3BfbzQV'
            'FRz+8NeMOY+ckpl2oipAjMyYd6daYu5hQYdwl5gOZ74fenyufCSNbzWLLF68BvVlI8Okg8WlnintNbJEOssA/X2Zzn8iN2QgMrFy'
            'NjJ6iPFcWN1fEXtlOUBy9qhHMV/r7TGFklxfdvhI7Ax/i4D9KTdg892oZ9kVyu4ddTCXHO9Klq6+7NvCtk4v6lL99VS9xDrD548x'
            '5IVQn9EuGsj7QD6KanjhvmVCWac0jJicVnLCV3hMM266/l3WFQGriHKyCzxGFPWiXiFb15AAqi2JDrSWIAgUquQRQ9EadfNE74/R'
            'vggHZFrEZPCBW5T786eSor4r8gc474/8I5hZ5C/CWTOuB7YbAPsDNZCxRbFM12T449/k+NW26V0kX3PqczIweZ8ENrUs0mMUjQkI'
            'DNJ+eEDAOBacg9Uf3Iu9Bzzv+a7nBrgs9CzqnCPU6ZL7zDd7h8SEgY55QGkF4cEBrBthXsGSnQejefOvJ5ZKHlcs3rkg2Wd1PrOM'
            '3teLd8YaQcolU8XBLCLOr5wa7TF1xfLzCYSnVN4747XobMKry3yHobSZzusPx4G4L4OWEzCbRCaTlBejjZiZYqJ9tNokU6ZNP219'
            'LG08FtpFlNDlIMslaLWaAbGWQpzyZpv71tldwUAUaIV0mcWQXTh7wBMUyajl+klGk721uewGy5RfPObbZhCYrjMarPwli6oUDDyl'
            'vkTaysL0HhJXsrKakbU2qG+7jvntPIlrB7LPFuQecs1NUhLzKGRhMUCk49qexR4Qn90LceNyn8F1Rmx6F5SQTp86kJfWyBZkugAG'
            '2ezxs5zujxIXH5gdIZY5dN9ia6eZ6z+QuRZdJ8wN5qTc1BrlhJwUBXGUsI+UnCaCf1LMQlW5Hs/BTBqQgUWFMhJSZSweZa0zU6I0'
            '89WiSqdJJk7K2fpJmt3b4D4u9jHUmmFT8II/mxfIJxBtYacPfne6zGf++VjheTfkXpg+I5ITeiSqVmsqdYCL+3Yf+kHA/+gYOZRk'
            'eBKfJLZo0EcmtmF5kKTa1P3p80ZB5zQEqhSPN4CauxasPyBygOJhoWF7kH1xSh66IRk+fArs7eLaYzWAZQuMN3RMe68C0VvuQJKf'
            'neDF7JqsC8j0NKuXo8Me/vzD6VHwkLwPwy2CEuv0E+Ly1N1LuDuOw8uuCJIBdTiEBVyvGRBAHca66yvxU5Jpyjt6Mx7EUpgoa1k9'
            'dlkgBbKW99xSXYsecuzi/gFuEFBrQA+hq6oZ1IIoxcrYoJ0OlGDQsGpwsXNiICfM/y8CsAotR/+q0APKgF86LAxN3HGoCoDghzus'
            'w2F1gcvfKAGIblO4tUncGTyTU/IVZLGxLIQY0j1EWWAlxvGVK9cKed6+ElWbHep0mIVYtuk+usNA2DZDAp5YZ6rVproxudgeK0Hi'
            'SqZ4DzJn+3ej4R/eDQCJ'
        ),
    },
    'software': {
        'empty': captured(
            'eJztVL1OwzAQHpl4Ai8nHqC1naRpFURFw/9ShKgARQhFbUorxW3JDxIbYkBsdEBhgEq8AQMDzDyKn4RzmkihUISYSc4+5+z7yenz'
            'R0ziBKRKnDo3emqmVJ9qjSnN0u9jasnHF7B9N+54YA873kK6p9fwDN8hztb0KM1ceKa1TFfSkIafz1uLxGEN4mhVi1ucGRZjNatq'
            'CpDJmDi6slL1Cpk8yOQmF7VGR76JnjWBB9XERKEsrEbHXc5FFpwZWj7EOS+xEq9V5iSXyUQmjzPpb4qSZkyXl3kZszmaozgEo2TA'
            '+yus7m5DK3RPPWj0fb8/OJ3/15h5ApAv5gUvR2JUPmq29k42tg/3W3vrJ/bBGvz8YM4qtVVfGvJ+DMLr9GOhqit73e4wiIo1Ma2S'
            'DyHvLv/ll5L3EMExeX5/Io4p9rHjJoKQi+AClgKv67ajYQDL3b7vjdyot7KUORWg+t/9v3af20UUF26MvH0D4Q5i1weB9ADDgYJ+'
            'HRD5EPYQ/u04CpVJXo9TI97WQRRm/KJhMGQ2jVoaqhV6hvwVk2PToMyqIwO2p0xWybLrM/c6qyenkqsia30O/SXK1Oc7jnqYF+UD'
            'zgeJrQ=='
        ),
        'busy': captured(
            'eJztVc1u00AQPnLiCXwZ9QES7zpOYhk1IikkpYeiqhEgq6qsxEksee3gHwS3iAPqjRyQOTSREAeuHDiUcx5ln4RZ2yu5iVOqnuvs'
            'n3d3Zr4df/tFaSlWqLQVq0P1mWhVtZH3GhE9yd4vVJOv/kDPs5OxA71g7DzJ1hoG7qGvFGuQb1ULE1r0WtE3M5e6J9vBU8UiXcXS'
            '2iY1KdFNQgyz3WLA06ViNcSsKn6Mp9c8vZJFjNGQ9tHSYLhRNISVYCGaBq5SygrnRNdkZR9ojdSo0dwTnKdrnq62wl+VSxYxGy4k'
            'jO0Yp/MkAr2mw+YGnr8+hmFkTx3oup7n+tP9p8bIawA52Oe8HrN5/d3p8Ozy5fHb8+HZi8vemyO4+8GYbbUn8tLl35fAnLGbMIGu'
            '7kwmQRiXMRGtKSvj3xaP5Z5F5hDJsf69+aFYLXaOGW8hCSkLP8FB6EzsURyE8Gzies7cjmeHB4VRiaqP2X9o9mmvzOLSjeFf/wKz'
            '/cT2gKE8QOAL6ncAmQ/RDOk/SuJITPEvy2wSb6sfR4W+aOgMlU1TTQ27Q/U96leiXLR0lZgdVMBRrmTNInpj614XeKSUfC6r1m3X'
            'O15ymyqNur7bi8gENboT92OchA5g4+OhHUFJKCh5IpjXFvsw2knZCTEGmdSjTtyW+gyfxKbreamSWOQ/SNS4qahsFw6e4T/C9YBH'
            'nF/tytxspW5zg3P9owB1WC5quKgbJsG08MWvCmFGh1olrfJrnn2IPYndsREsc6IRxAG4fuyEYTKP78m87MM2q/6yVj8RQL/iPNMK'
            'R/8AM7YUpw=='
        ),
        'post-turn': captured(
            'eJztVk1P20AQPfbEL/BlxLEH8K7jJK4rUB3aQKMKhEBtZSHkJhtiyWunjt2PG+qh4gaVqnAApKqHXnuoVCpVvfBT/Es6u7GLk9gp'
            '4UxYe42982b2+c1LlJpih0pdsVep3hNnVa2MZo2Imcj/91QzOf8BDc+JOwwaQYfdk88qBq6hTxV7fbRUTUNoOmvpXJWQuped1xcU'
            'm1iKrdVNalKim4QYZr3GIRmeKHZF3FXFH0+GZ8nwKBviGgNpEyMNjgvFifBcWVhNBZ9SylNwomvZwd/QJbJEjWpJ8mR4kQzPJ9If'
            '5YfMKC8PszImc2z24wHoSzpcXcKjrQ3YHTgHDCzX81z/oHzXmPkCILsoA1+OeH/55ebu9v6TjRc7u9uP9xvP12D2B3PW1YbgxUpO'
            'T4CzjhtzUd0y63aDMMrXRLRqdvDk8+HduOHIOERxXHy/+qLYNb6DjNdQhJSH72ExZF2nHQUhPOy6Hus7UW9lMQ3KSfWO/duyTxt5'
            'Fec6Jjn+BdzxY8cDjvYAgS+kvwqofBj0UP7tOBqIW8nHE3kTu9WPBqm/aAiGzqappobTivoa/StW9mq6SsxVdMD2yMmqafbKRF+n'
            '9WRW8iHvWuPQUyijmCKPOpuNIpightV130VxyABPPm6aCUlCKsmWUF5drMNsrTwIMdal1aNPjFu9rC+rTddHo8hiUf+QVY2L0oNP'
            'l4N7+I9x3eIj9q9aGTcT1F1d4r3mWoA+nD3U8KFumARpSQ6/FRgzAmqFshq1uXwRJcROxQiVsUEbogBcP2JhGPejGypPvthq0VfW'
            '+VcsoFmwn4P5gO7j+y2C8eet5+e8Ab8VWy/K7OL3VrMgQL6nuTL8QUEUZQjy1F0HzGCuMZYjB7WWp+8aqpA92WCfChpsFkFuGdLU'
            'rzKBVP8HlOvB5PRYNIAECpnTEfxGPSZ/a/TjV56LbkaMZtqqCyUqlvVoTStkb1lH6pZI/+xgVwOhD/QKbD0TfVC10pJbsolkxwhQ'
            'UtYfNzXl1jgLfwFAH9hX'
        ),
        'suggestion': captured(
            'eJztV0tv00AQPnLqL/BlxBGh1mvHeRBERRJISoRA0ApQhJBJNoklv7DXLdwqDogTFAmFA62EOHDlgARICCHlp/iXMLu2UzdZhwYB'
            'J1K/6t35Znb2m2/XSkXpBUpV6W1qxphfVbWU3HXC70T8f1+tx4efoGmb0YBC0xvQM6KtVMM+2jWl10m6qqmJlt719F4WkIadXTtr'
            'So80lJ5erWt1jRh1Qmr1asWBeHKg9Er8rcr/nHjyNp48zw7+jIZaGy1rDnbkF+LkwsJoStiqaU4KTgw9O51dbZ2sa7VygfN4chRP'
            'DufcP88fwqN43M/CmPdxw49CMNYNmH6Byze3YCc0RxQalm1b7qh41Oj5CCB7KALfYI6/ce/Gzq0HV7fubu/cuvKgeacFy3/os6o2'
            'eV4a8ZsDcOjAihwe3QYdDr2A5WMiejk7nfj1/v/jlEeWQyTH0cfpO6VXcbYx4xUkoeYET+BsQIdmn3kBXBxaNvVNNr50NjXKUfV/'
            '9n83+1ozz+JcxcQvv4JjupFpg4PyAJ7Lqb8JyHwIx0j/fsRC/ip+diBeYrW6LEz1RUcwVDZdret4u6Q+Qv2KlPsVQyX1TVTAfqJk'
            '5dR7aa6u03gyKXmaV62T0AsoiY1Mo94uR+GZ0GqNofWYRQEFvLg4aMopCSklu5x5Vd4PvXXzIKTWEVKPOnFS6kV8WWyGkRwyiUX+'
            'QxY1dkpPZzEcHMMvhOs3fnz8aiPLzVzqpl/wXbvloQ5njTo2GrU6wbTE+x8kwoyAupRWSZmLiShI7IINZxkN+8A8sFxGgyDy2SmZ'
            'Jya2LFuyDt9jAG3JeEarAZ3D+ZXBuKvG83lVg29Kz5B5tnDdaksMxDyt5OE7EkLmwcun7thgSeaaJ3zkoFr59B1DSbMnCuyVpMCW'
            'JcgqQlrYlXGk6gwoV4Pxm5e8AARQQM0Bzy8bU7HX8KOHtoVqRmrttFTXClgs4tHbjYDu0YHgLRH6OcCqBqJdMEpw8zqvg3IjDbkr'
            'ikhUDAclRfVxWlHuFk7NTPbQPWlzreFxtNmeJ6o0X51JvUq1TzY1RPtT4ieC+Vvil4QpE7902lq0b/ljGqAGYiHBWsGqiRvRFz9g'
            '+m7b8i/AbWYGDPYsNobQMW0bhtTk4wkBZ+ZhNAIcHw3PA6PYlqYONc4PPN8LKZjg26Z7Hkx3ALvoefgELJxddG2IBS+MRiMaMiQT'
            '7kxZeEyWfyyvpSLtWM3g26oGSwRTZnBuVfz3hRokW+SlIGLlPL36kNJfl5+mN7KYyZYqUDUvQJzm3Rnn/q0ocQ4Hs88BHDrguCEZ'
            'M8wUK/kOWMBIvt0q8zs1vfMT8rI6ig=='
        ),
        'typed': captured(
            'eJztV01v00AQPXKq+AG+jDihCrVeO85Hg6hICilECFRaAYoQMskmseQv7DWFW8UBcYIiofRAK6EeuHJAAiSEkPpT/EuYXdupm6zT'
            'BgEnUtvrej1vZmffvPUqFaUTKFWls6oZQ35V1VLS6oS3RPz/UK3H+5+haZtRj0LT69Fzoq9Uw3e0m0pnPXlVTU20tNXTtiwgDTu7'
            'ri8oHdJQOnq1rtU1YtQJqdWrFQfi0a7SKfGnKv9z4tH7ePQqO/g9GmottKw5+CK/ECcXFkZTwl5Nc1JwYujZ6TzVlsiSVisXOI9H'
            'B/Fof8L9q/whPIrbnSyMSR+3/SgEY8mAo69w9c4N2ArNAYWGZduWOygeNXo+AMhuisCXmeMvP7i9tfHo+o37m1sb1x41763B7B/6'
            'rKpNnpdGvLcLDu1ZkcOjW6b9vhewfExEL2enE7/b+X+c8chyiOQ4+HT0QelUnE3MeAVJqDnBc7gQ0L7ZZV4Al/uWTX2TDa9cSI1y'
            'VP2f/d/NvtbMszhXMfGbb+CYbmTa4KA8gOdy6q8CMh/CIdK/G7GQP4pf7oqHWK0uC1N90REMlU1X6zo2V9QnqF+R8rBiqKS+igrY'
            'TZSsnHovTdR1Gk8mJS/yqnUSegolsZFp1PvZKDwTWq3Rt56xKKCAFxcHTTklIaVkmzOvyt9Db+08CKmtC6lHnTgp9SK+LDbDSA6Z'
            'xCL/IYsaX0pPZzocHMMpwvUbPz5+tZHlZiJ1R1/xWWvNQx3OOnXsNGp1gmmJdz5KhBkBdSmtkjIXE1GQ2CkbzjIadoF5YLmMBkHk'
            'szMyT0xsWbZk7R9iAC3JeAbzAS3i/Mpg3Hnj+TKvwXelY8g8W7hutSQGYp7m8vADCSHz4OVTd2wwI3PNEz5yUGv59B1DSbMnCuyt'
            'pMBmJcgqQpr6KuNI1TFQrgbjvTe8AARQQM0ezy8bUvGt4UePbQvVjNRaaakuFLBYxKO3GgHdpj3BWyL0s4dVDURbMUpw5xavg3Ij'
            'DbktikhUDAclRfVxVlFuF07NWPbQPWlxreFxtNi2J6o0X51JvUq1TzY1RPtT4ieC+Vvil4QpE7902tZo1/KHNEANxEKChYJVEz9E'
            'X/+Eow+blr8Cd5kZMNi22BBCx7Rt6FOTjycEnJnH0QBwfDS8BIxiX5o61Dg/8HwvpGCCb5vuJTDdHjxFz/3nYOHsomtDLHhhNBjQ'
            'kCGZ8MuUhcdk+cfyWirSjvkMvs9rMEMwZQaL8+IfFmqQbJGXgoiV8+zqQ0p/XX6a3sBiJpupQNW8AHGat8ec+7eixDkcjLcDOHTA'
            'cUMyZhgrVrIPmMJI9m6VyS817L7YOJ/br5+y+c6FExRFcKpEauX1X8UhWNM='
        ),
        'permission': captured(
            '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'
        ),
    },
}

MOUSE_REPORT = b"\x1b[<35;20;10M"
