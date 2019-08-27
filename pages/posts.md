---
layout: page
title: Posts
permalink: /Posts/
feature-img: "assets/img/pexels/circuit.jpeg"
---

Links to all posts.

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>
