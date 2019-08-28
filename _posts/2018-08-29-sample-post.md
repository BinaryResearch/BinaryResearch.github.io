---
layout: post
title: Sample post
tags: [test, sample]
feature-img: assets/img/future-city-night-art.jpg
author-id: julian
---

# This is a sample

Check text width. Sample text:

example link: [google.com](https://google.com)

Access to the technical reference manual allows us to determine what APROM and ISP are. From Chapter 6: Functional Description, section 4.4.1: Flash Memory Organization, page 191:

>The NuMicro NUC200 Series flash memory consists of program memory (APROM), Data Flash, ISP loader program memory (LDROM), and user configuration. Program memory is main memory for user applications and called APROM. User can write their application to APROM and set system to boot from APROM.
ISP loader program memory is designed for a loader to implement In-System-Programming function. LDROM is independent to APROM and system can also be set to boot from LDROM. Therefore, user can user LDROM to avoid system boot fail when code of APROM was corrupted.

And from Chapter 6: Functional Description, section 4.4.5: In-System-Programming (ISP), page 199:

```css
%padding-regular {
  //padding: $padding-small $padding-x-large; // original
  padding: $padding-medium;
  @media (max-width: 1000px) {
    padding: $padding-small * 1.5 $padding-large / 1.6;
  }
  @media (max-width: 576px) {
    padding: $padding-small;
  }
}
```

