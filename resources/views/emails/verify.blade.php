<x-mail::message>
# Introduction

Thank you for signing up. 
Your six-digit code is <b>{{$pin}}</b>

<x-mail::button :url="''">
Button Text
</x-mail::button>

Thanks,<br>
{{ config('app.name') }}
</x-mail::message>
